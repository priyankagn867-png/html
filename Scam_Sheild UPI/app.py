from flask import Flask, render_template, request, jsonify
from datetime import datetime
import statistics
import sqlite3
import json
import re
import uuid
import os


app = Flask(__name__)


# =========================================================
# SCAMSHIELD UPI 4.1
# Educational / Hackathon Fraud-Risk Prototype
# SQLite Persistent Storage
# =========================================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "scamshield.db")


UPI_PATTERN = re.compile(
    r"^[A-Za-z0-9._-]{2,}@[A-Za-z]{2,}$"
)


SCAM_KEYWORDS = {
    "urgent": 12,
    "immediately": 10,
    "prize": 15,
    "lottery": 20,
    "winner": 12,
    "refund": 12,
    "verify": 10,
    "verification": 10,
    "kyc": 15,
    "blocked": 15,
    "unblock": 15,
    "collect": 10,
    "reward": 12,
    "cashback": 8,
    "otp": 15,
    "pin": 15,
    "account suspended": 20,
    "limited time": 10
}


# =========================================================
# DATABASE
# =========================================================

def get_db_connection():
    connection = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    connection = get_db_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                amount REAL NOT NULL,
                payee TEXT NOT NULL,
                upi_id TEXT NOT NULL,
                note TEXT DEFAULT '',
                new_payee INTEGER DEFAULT 0,
                decision TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_label TEXT NOT NULL,
                reasons TEXT NOT NULL,
                advice TEXT NOT NULL,
                recipient_trust_score INTEGER NOT NULL,
                recipient_trust_level TEXT NOT NULL,
                behavior_score INTEGER NOT NULL,
                behavior_level TEXT NOT NULL,
                behavior_deviation REAL NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_transactions_upi_id
            ON transactions(upi_id)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_transactions_created_at
            ON transactions(created_at)
            """
        )

        connection.commit()

    finally:
        connection.close()


# =========================================================
# HELPERS
# =========================================================

def normalize_upi(upi_id):
    return str(upi_id or "").strip().lower()


def parse_boolean(value):
    if isinstance(value, bool):
        return value

    return str(value).lower() in (
        "true",
        "1",
        "yes",
        "on"
    )


def contains_phrase(text, phrase):
    pattern = (
        r"\b"
        + re.escape(phrase.lower())
        + r"\b"
    )

    return bool(
        re.search(
            pattern,
            text.lower()
        )
    )


def row_to_transaction(row):
    if row is None:
        return None

    transaction = dict(row)

    try:
        transaction["reasons"] = json.loads(
            transaction.get(
                "reasons",
                "[]"
            )
        )

    except (
        json.JSONDecodeError,
        TypeError
    ):
        transaction["reasons"] = []

    transaction["new_payee"] = bool(
        transaction.get(
            "new_payee",
            0
        )
    )

    return transaction


# =========================================================
# DATABASE HISTORY
# =========================================================

def get_transaction_history(limit=100):
    connection = get_db_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM transactions
            ORDER BY
                created_at DESC,
                rowid DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

    finally:
        connection.close()

    return [
        row_to_transaction(row)
        for row in rows
    ]


def recipient_history(upi_id):
    normalized = normalize_upi(
        upi_id
    )

    connection = get_db_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM transactions
            WHERE LOWER(upi_id) = ?
            ORDER BY
                created_at DESC,
                rowid DESC
            """,
            (normalized,)
        ).fetchall()

    finally:
        connection.close()

    return [
        row_to_transaction(row)
        for row in rows
    ]


# =========================================================
# SCAM LANGUAGE DETECTION
# =========================================================

def detect_scam_language(note):
    note = str(
        note or ""
    ).lower()

    detected = []
    keyword_score = 0

    for phrase, weight in SCAM_KEYWORDS.items():

        if contains_phrase(
            note,
            phrase
        ):
            detected.append(
                phrase
            )

            keyword_score += weight

    keyword_score = min(
        keyword_score,
        35
    )

    return {
        "detected": bool(detected),
        "keywords": detected,
        "score_contribution": keyword_score
    }


# =========================================================
# RECIPIENT INTELLIGENCE
# =========================================================

def calculate_recipient_trust(data):
    upi_id = normalize_upi(
        data.get(
            "upi_id"
        )
    )

    amount = float(
        data.get(
            "amount",
            0
        )
    )

    new_payee = parse_boolean(
        data.get(
            "new_payee",
            False
        )
    )

    history = recipient_history(
        upi_id
    )

    trust_score = 70
    signals = []

    # -----------------------------------------------------
    # UPI FORMAT
    # -----------------------------------------------------

    if UPI_PATTERN.fullmatch(
        upi_id
    ):
        signals.append(
            "Recipient UPI ID has a valid-looking format."
        )

    else:
        trust_score -= 25

        signals.append(
            "Recipient UPI ID format looks unusual."
        )

    # -----------------------------------------------------
    # NEW RECIPIENT
    # -----------------------------------------------------

    if new_payee:
        trust_score -= 20

        signals.append(
            "Recipient is marked as a first-time payee."
        )

    # -----------------------------------------------------
    # PREVIOUS RECIPIENT HISTORY
    # -----------------------------------------------------

    if history:
        allowed = sum(
            1
            for item in history
            if item.get("decision") == "ALLOW"
        )

        reviewed = sum(
            1
            for item in history
            if item.get("decision") == "REVIEW"
        )

        blocked = sum(
            1
            for item in history
            if item.get("decision") == "BLOCK"
        )

        if allowed >= 3:
            trust_score += 18

            signals.append(
                "Recipient has multiple previous lower-risk transactions."
            )

        elif allowed >= 1:
            trust_score += 8

            signals.append(
                "Recipient has previous lower-risk transaction history."
            )

        if reviewed > 0:
            trust_score -= 10

            signals.append(
                "Recipient has previously required additional review."
            )

        if blocked > 0:
            trust_score -= 35

            signals.append(
                "Recipient has previously triggered a high-risk alert."
            )

    else:
        trust_score -= 10

        signals.append(
            "No previous transaction history exists for this recipient."
        )

    if (
        amount >= 50000
        and not history
    ):
        trust_score -= 15

        signals.append(
            "High-value payment is being made to a recipient with no history."
        )

    trust_score = max(
        0,
        min(
            100,
            trust_score
        )
    )

    if trust_score >= 70:
        trust_level = "HIGH TRUST"

    elif trust_score >= 40:
        trust_level = "MEDIUM TRUST"

    else:
        trust_level = "LOW TRUST"

    return {
        "trust_score": trust_score,
        "trust_level": trust_level,
        "signals": signals,
        "previous_transactions": len(history)
    }


# =========================================================
# BEHAVIORAL ANOMALY DETECTION
# =========================================================

def calculate_behavioral_risk(data):
    current_amount = float(
        data.get(
            "amount",
            0
        )
    )

    history = get_transaction_history(
        limit=100
    )

    # Only previous ALLOW transactions are used.
    # The current transaction is analyzed before it is saved.

    previous_amounts = [
        float(
            item.get(
                "amount",
                0
            )
        )
        for item in history
        if (
            item.get("decision") == "ALLOW"
            and float(
                item.get(
                    "amount",
                    0
                )
            ) > 0
        )
    ]

    sample_size = len(
        previous_amounts
    )

    if sample_size == 0:
        return {
            "available": False,
            "sample_size": 0,
            "average_amount": 0,
            "median_amount": 0,
            "baseline_amount": 0,
            "current_amount": current_amount,
            "deviation_ratio": 1,
            "behavior_score": 0,
            "behavior_level": "LEARNING",
            "signals": [
                (
                    "More lower-risk transactions are needed "
                    "to establish a behavioral spending baseline."
                )
            ]
        }

    average_amount = (
        sum(previous_amounts)
        / sample_size
    )

    median_amount = statistics.median(
        previous_amounts
    )

    baseline_amount = median_amount

    if baseline_amount <= 0:
        baseline_amount = average_amount

    if baseline_amount > 0:
        deviation_ratio = (
            current_amount
            / baseline_amount
        )

    else:
        deviation_ratio = 1

    deviation_ratio = round(
        deviation_ratio,
        2
    )

    behavior_score = 0
    signals = []

    if sample_size < 3:
        signals.append(
            (
                "Behavioral profile is still developing "
                "because fewer than three lower-risk "
                "transactions are available."
            )
        )

    if deviation_ratio >= 10:
        behavior_score += 30

        signals.append(
            (
                "Current payment is extremely higher than "
                "the recent lower-risk spending baseline."
            )
        )

    elif deviation_ratio >= 5:
        behavior_score += 22

        signals.append(
            (
                "Current payment is significantly higher "
                "than the recent lower-risk spending baseline."
            )
        )

    elif deviation_ratio >= 3:
        behavior_score += 15

        signals.append(
            (
                "Current payment is noticeably higher than "
                "the recent lower-risk spending baseline."
            )
        )

    elif deviation_ratio >= 2:
        behavior_score += 8

        signals.append(
            (
                "Current payment is moderately higher than "
                "the recent lower-risk spending baseline."
            )
        )

    else:
        signals.append(
            (
                "Current payment is reasonably close to "
                "the recent lower-risk spending baseline."
            )
        )

    if (
        current_amount >= 20000
        and deviation_ratio >= 3
    ):
        behavior_score += 5

        signals.append(
            (
                "A large payment and unusual spending "
                "deviation occurred together."
            )
        )

    behavior_score = min(
        behavior_score,
        35
    )

    if behavior_score >= 25:
        behavior_level = "HIGH"

    elif behavior_score >= 10:
        behavior_level = "MEDIUM"

    else:
        behavior_level = "LOW"

    return {
        "available": True,
        "sample_size": sample_size,
        "average_amount": round(
            average_amount,
            2
        ),
        "median_amount": round(
            median_amount,
            2
        ),
        "baseline_amount": round(
            baseline_amount,
            2
        ),
        "current_amount": current_amount,
        "deviation_ratio": deviation_ratio,
        "behavior_score": behavior_score,
        "behavior_level": behavior_level,
        "signals": signals
    }


# =========================================================
# MAIN FRAUD RISK ENGINE
# =========================================================

def analyze_transaction(data):
    amount = float(
        data.get(
            "amount",
            0
        )
    )

    upi_id = normalize_upi(
        data.get(
            "upi_id"
        )
    )

    note = str(
        data.get(
            "note",
            ""
        )
    ).lower()

    new_payee = parse_boolean(
        data.get(
            "new_payee",
            False
        )
    )

    risk_score = 0
    reasons = []

    # -----------------------------------------------------
    # 1. TRANSACTION AMOUNT
    # -----------------------------------------------------

    if amount >= 50000:
        risk_score += 30

        reasons.append(
            "High-value transaction detected."
        )

    elif amount >= 20000:
        risk_score += 15

        reasons.append(
            "Transaction amount is significantly high."
        )

    elif amount >= 10000:
        risk_score += 8

        reasons.append(
            "Transaction amount is above the normal demo range."
        )

    # -----------------------------------------------------
    # 2. UPI FORMAT
    # -----------------------------------------------------

    if not UPI_PATTERN.fullmatch(
        upi_id
    ):
        risk_score += 20

        reasons.append(
            "Recipient UPI ID format looks unusual."
        )

    # -----------------------------------------------------
    # 3. NEW RECIPIENT
    # -----------------------------------------------------

    if new_payee:
        risk_score += 15

        reasons.append(
            "Payment is being made to a new recipient."
        )

    # -----------------------------------------------------
    # 4. SCAM LANGUAGE
    # -----------------------------------------------------

    scam_language = detect_scam_language(
        note
    )

    risk_score += scam_language[
        "score_contribution"
    ]

    if scam_language["keywords"]:
        reasons.append(
            "Possible scam language detected: "
            + ", ".join(
                scam_language["keywords"]
            )
        )

    # -----------------------------------------------------
    # 5. RECIPIENT INTELLIGENCE
    # -----------------------------------------------------

    recipient = calculate_recipient_trust(
        data
    )

    trust_score = recipient[
        "trust_score"
    ]

    if trust_score < 30:
        risk_score += 20

        reasons.append(
            "Recipient has a very low trust score."
        )

    elif trust_score < 50:
        risk_score += 10

        reasons.append(
            "Recipient trust score is below the preferred range."
        )

    # -----------------------------------------------------
    # 6. BEHAVIORAL ANALYSIS
    # -----------------------------------------------------

    behavior = calculate_behavioral_risk(
        data
    )

    risk_score += behavior[
        "behavior_score"
    ]

    if behavior["available"]:

        if behavior["behavior_level"] == "HIGH":
            reasons.append(
                (
                    "Behavioral anomaly detected: the payment "
                    "is highly unusual compared with recent "
                    "lower-risk spending."
                )
            )

        elif behavior["behavior_level"] == "MEDIUM":
            reasons.append(
                (
                    "Behavioral review recommended: "
                    "the payment differs from recent "
                    "lower-risk spending."
                )
            )

    # -----------------------------------------------------
    # 7. MULTI-SIGNAL COMBINATIONS
    # -----------------------------------------------------

    if (
        new_payee
        and amount >= 20000
        and scam_language["keywords"]
    ):
        risk_score += 10

        reasons.append(
            (
                "Multiple risk signals occurred together: "
                "new recipient, high amount and suspicious language."
            )
        )

    if (
        new_payee
        and behavior["behavior_level"] == "HIGH"
    ):
        risk_score += 5

        reasons.append(
            (
                "A new recipient and a major behavioral "
                "anomaly were detected together."
            )
        )

    risk_score = max(
        0,
        min(
            100,
            risk_score
        )
    )

    # -----------------------------------------------------
    # FINAL DECISION
    # -----------------------------------------------------

    if risk_score >= 60:
        decision = "BLOCK"
        risk_label = "High risk"

        advice = (
            "Simulated interception triggered. "
            "Do not continue until the recipient is "
            "independently verified through a trusted channel."
        )

    elif risk_score >= 30:
        decision = "REVIEW"
        risk_label = "Needs review"

        advice = (
            "Pause the payment and verify the recipient "
            "and payment request before continuing."
        )

    else:
        decision = "ALLOW"
        risk_label = "Lower risk"

        advice = (
            "No major configured warning threshold was reached. "
            "This does not guarantee that the payment is safe."
        )

    if not reasons:
        reasons.append(
            "No configured fraud warning signal was detected."
        )

    return {
        "score": risk_score,
        "risk_score": risk_score,
        "decision": decision,
        "risk_label": risk_label,
        "risk_level": risk_label,
        "reasons": reasons,
        "advice": advice,
        "recipient_intelligence": recipient,
        "scam_language": scam_language,
        "behavioral_intelligence": behavior
    }


# =========================================================
# CREATE TRANSACTION
# =========================================================

def create_transaction(data, result):
    recipient = result[
        "recipient_intelligence"
    ]

    behavior = result[
        "behavioral_intelligence"
    ]

    return {
        "id": str(
            uuid.uuid4()
        )[:8].upper(),

        "created_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "amount": float(
            data.get(
                "amount",
                0
            )
        ),

        "payee": (
            str(
                data.get(
                    "payee",
                    ""
                )
            ).strip()
            or "Unknown"
        ),

        "upi_id": (
            normalize_upi(
                data.get(
                    "upi_id"
                )
            )
            or "Not provided"
        ),

        "note": str(
            data.get(
                "note",
                ""
            )
        ).strip(),

        "new_payee": parse_boolean(
            data.get(
                "new_payee",
                False
            )
        ),

        "decision": result[
            "decision"
        ],

        "score": result[
            "score"
        ],

        "risk_score": result[
            "risk_score"
        ],

        "risk_label": result[
            "risk_label"
        ],

        "reasons": result[
            "reasons"
        ],

        "advice": result[
            "advice"
        ],

        "recipient_trust_score": recipient[
            "trust_score"
        ],

        "recipient_trust_level": recipient[
            "trust_level"
        ],

        "behavior_score": behavior[
            "behavior_score"
        ],

        "behavior_level": behavior[
            "behavior_level"
        ],

        "behavior_deviation": behavior[
            "deviation_ratio"
        ]
    }


# =========================================================
# SAVE TRANSACTION TO SQLITE
# =========================================================

def save_transaction(transaction):
    connection = get_db_connection()

    try:
        connection.execute(
            """
            INSERT INTO transactions (
                id,
                created_at,
                amount,
                payee,
                upi_id,
                note,
                new_payee,
                decision,
                score,
                risk_score,
                risk_label,
                reasons,
                advice,
                recipient_trust_score,
                recipient_trust_level,
                behavior_score,
                behavior_level,
                behavior_deviation
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                transaction["id"],
                transaction["created_at"],
                transaction["amount"],
                transaction["payee"],
                transaction["upi_id"],
                transaction["note"],

                1
                if transaction["new_payee"]
                else 0,

                transaction["decision"],
                transaction["score"],
                transaction["risk_score"],
                transaction["risk_label"],

                json.dumps(
                    transaction["reasons"]
                ),

                transaction["advice"],
                transaction["recipient_trust_score"],
                transaction["recipient_trust_level"],
                transaction["behavior_score"],
                transaction["behavior_level"],
                transaction["behavior_deviation"]
            )
        )

        connection.commit()

    finally:
        connection.close()


# =========================================================
# CLEAR ALL TRANSACTIONS
# =========================================================

def clear_all_transactions():
    connection = get_db_connection()

    try:
        connection.execute(
            "DELETE FROM transactions"
        )

        connection.commit()

    finally:
        connection.close()


# =========================================================
# ROUTES
# =========================================================

@app.route("/")
def home():
    return render_template(
        "index.html"
    )


# =========================================================
# HEALTH API
# =========================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health():
    return jsonify({
        "status": "ok",
        "project": "ScamShield UPI 4.1",
        "engine": (
            "Transaction Risk + Recipient Intelligence "
            "+ Scam Language + Behavioral Analysis"
        ),
        "database": "SQLite",
        "persistent_history": True,
        "real_upi_connected": False
    })


# =========================================================
# ANALYZE TRANSACTION API
# =========================================================

@app.route(
    "/api/analyze",
    methods=["POST"]
)
def analyze():
    data = request.get_json(
        silent=True
    ) or {}

    try:
        amount = float(
            data.get(
                "amount",
                0
            )
        )

        if amount <= 0:
            return jsonify({
                "ok": False,
                "error": "Enter an amount greater than zero."
            }), 400

        if not str(
            data.get(
                "payee",
                ""
            )
        ).strip():
            return jsonify({
                "ok": False,
                "error": "Recipient name is required."
            }), 400

        if not str(
            data.get(
                "upi_id",
                ""
            )
        ).strip():
            return jsonify({
                "ok": False,
                "error": "Recipient UPI ID is required."
            }), 400

        # Analyze first.
        # Save only after the analysis is complete.
        #
        # This prevents the current transaction from
        # affecting its own recipient or behavior analysis.

        result = analyze_transaction(
            data
        )

        transaction = create_transaction(
            data,
            result
        )

        save_transaction(
            transaction
        )

        return jsonify({
            "ok": True,
            "result": result,
            "transaction": transaction
        })

    except (
        TypeError,
        ValueError
    ):
        return jsonify({
            "ok": False,
            "error": "Please enter valid transaction details."
        }), 400

    except sqlite3.Error as error:
        print(
            "SQLite error:",
            error
        )

        return jsonify({
            "ok": False,
            "error": (
                "The transaction could not be saved "
                "to the local database."
            )
        }), 500


# =========================================================
# TRANSACTION HISTORY API
# =========================================================

@app.route(
    "/api/transactions",
    methods=["GET"]
)
def transaction_history():
    try:
        saved = get_transaction_history(
            limit=100
        )

        return jsonify({
            "count": len(saved),
            "transactions": saved
        })

    except sqlite3.Error as error:
        print(
            "SQLite error:",
            error
        )

        return jsonify({
            "count": 0,
            "transactions": [],
            "error": "Unable to read transaction history."
        }), 500


# =========================================================
# CLEAR TRANSACTION HISTORY API
# =========================================================

@app.route(
    "/api/transactions/clear",
    methods=["DELETE"]
)
def clear_transaction_history():
    try:
        clear_all_transactions()

        return jsonify({
            "ok": True,
            "message": "Transaction history cleared successfully."
        })

    except sqlite3.Error as error:
        print(
            "SQLite error:",
            error
        )

        return jsonify({
            "ok": False,
            "error": "Unable to clear transaction history."
        }), 500


# =========================================================
# INITIALIZE DATABASE
# =========================================================

initialize_database()


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )