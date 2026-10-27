// =========================================================
// SCAMSHIELD UPI 4.1
// PAGE NAVIGATION + FRAUD ANALYSIS + SQLITE HISTORY
// =========================================================


// =========================================================
// ELEMENTS
// =========================================================

const analyzeForm =
    document.getElementById("analyzeForm");

const analyzeButton =
    document.getElementById("analyzeButton");


const amountInput =
    document.getElementById("amount");

const payeeInput =
    document.getElementById("payee");

const upiInput =
    document.getElementById("upi_id");

const noteInput =
    document.getElementById("note");


// NEW: FRAUD MESSAGE INPUT
const fraudMessageInput =
    document.getElementById("fraud_message");


const newPayeeInput =
    document.getElementById("new_payee");


const formError =
    document.getElementById("formError");


const emptyState =
    document.getElementById("emptyState");

const resultContent =
    document.getElementById("resultContent");


const scoreValue =
    document.getElementById("scoreValue");

const decisionBadge =
    document.getElementById("decisionBadge");

const scoreMeter =
    document.getElementById("scoreMeter");

const riskLabel =
    document.getElementById("riskLabel");


const trustLevel =
    document.getElementById("trustLevel");

const trustScore =
    document.getElementById("trustScore");

const previousTransactions =
    document.getElementById("previousTransactions");

const trustMeter =
    document.getElementById("trustMeter");


const scamStatus =
    document.getElementById("scamStatus");

const scamDescription =
    document.getElementById("scamDescription");

const keywordContainer =
    document.getElementById("keywordContainer");


const behaviorLevel =
    document.getElementById("behaviorLevel");

const behaviorDeviation =
    document.getElementById("behaviorDeviation");

const behaviorBaseline =
    document.getElementById("behaviorBaseline");

const behaviorScore =
    document.getElementById("behaviorScore");


const reasonList =
    document.getElementById("reasonList");

const trustSignals =
    document.getElementById("trustSignals");

const behaviorSignals =
    document.getElementById("behaviorSignals");


const adviceText =
    document.getElementById("adviceText");


const transactionRows =
    document.getElementById("transactionRows");


const clearHistoryBtn =
    document.getElementById("clearHistoryBtn");


const totalCount =
    document.getElementById("totalCount");

const reviewCount =
    document.getElementById("reviewCount");

const blockCount =
    document.getElementById("blockCount");


// =========================================================
// ANALYSIS OVERLAY
// =========================================================

const analysisOverlay =
    document.getElementById("analysisOverlay");


const analysisProgress =
    document.getElementById("analysisProgress");


const analysisStatus =
    document.getElementById("analysisStatus");


const scanSteps = [

    document.getElementById("scanStep1"),

    document.getElementById("scanStep2"),

    document.getElementById("scanStep3"),

    document.getElementById("scanStep4")

];


// =========================================================
// BASIC HELPERS
// =========================================================

function setText(element, value) {

    if (!element) {
        return;
    }

    element.textContent = value;

}


function wait(milliseconds) {

    return new Promise(resolve => {

        setTimeout(
            resolve,
            milliseconds
        );

    });

}


function getScore(result) {

    const score = Number(

        result?.risk_score ??

        result?.score ??

        0

    );


    return Math.max(

        0,

        Math.min(
            100,
            score
        )

    );

}


function formatAmount(value) {

    const amount =
        Number(value || 0);


    return new Intl.NumberFormat(

        "en-IN",

        {

            style: "currency",

            currency: "INR",

            maximumFractionDigits: 0

        }

    ).format(amount);

}


function formatTime(value) {

    if (!value) {
        return "—";
    }


    const parts =
        String(value).split(" ");


    if (parts.length === 2) {

        return parts[1];

    }


    return value;

}


// =========================================================
// ANALYSIS OVERLAY
// =========================================================

function resetAnalysisOverlay() {

    scanSteps.forEach(step => {

        if (!step) {
            return;
        }


        step.classList.remove(

            "active",

            "complete"

        );


        const result =
            step.querySelector(
                ".step-result"
            );


        if (result) {

            result.textContent =
                "...";

        }

    });


    if (analysisProgress) {

        analysisProgress.style.width =
            "0%";

    }


    setText(

        analysisStatus,

        "Initializing ScamShield engine..."

    );

}


function openAnalysisOverlay() {

    resetAnalysisOverlay();


    if (!analysisOverlay) {
        return;
    }


    analysisOverlay.hidden =
        false;


    analysisOverlay.classList.remove(
        "hidden"
    );

}


function closeAnalysisOverlay() {

    if (!analysisOverlay) {
        return;
    }


    analysisOverlay.hidden =
        true;


    analysisOverlay.classList.add(
        "hidden"
    );

}


async function runAnalysisAnimation() {

    const messages = [

        "Checking transaction context...",

        "Evaluating recipient intelligence...",

        "Scanning fraud message for social-engineering patterns...",

        "Comparing behavioral spending patterns..."

    ];


    for (

        let index = 0;

        index < scanSteps.length;

        index++

    ) {

        const step =
            scanSteps[index];


        if (!step) {
            continue;
        }


        step.classList.add(
            "active"
        );


        setText(

            analysisStatus,

            messages[index]

        );


        if (analysisProgress) {

            analysisProgress.style.width =

                `${(index + 1) * 25}%`;

        }


        await wait(450);


        step.classList.remove(
            "active"
        );


        step.classList.add(
            "complete"
        );


        const result =
            step.querySelector(
                ".step-result"
            );


        if (result) {

            result.textContent =
                "✓";

        }

    }


    setText(

        analysisStatus,

        "Risk assessment complete."

    );


    await wait(350);

}


// =========================================================
// PAGE NAVIGATION
// =========================================================

function showPage(pageId) {

    const pages =
        document.querySelectorAll(
            ".app-page"
        );


    pages.forEach(page => {

        page.classList.remove(
            "active-page"
        );

    });


    const selectedPage =
        document.getElementById(
            pageId
        );


    if (!selectedPage) {

        console.error(

            "Page not found:",

            pageId

        );

        return;

    }


    selectedPage.classList.add(
        "active-page"
    );


    document
        .querySelectorAll(".nav-btn")
        .forEach(button => {

            button.classList.remove(
                "active"
            );


            if (

                button.dataset.pageTarget ===

                pageId

            ) {

                button.classList.add(
                    "active"
                );

            }

        });


    if (pageId === "historyPage") {

        loadTransactions();

    }

}


// =========================================================
// CONNECT PAGE BUTTONS
// =========================================================

document
    .querySelectorAll(
        "[data-page-target]"
    )
    .forEach(button => {

        button.addEventListener(

            "click",

            () => {

                showPage(

                    button.dataset.pageTarget

                );

            }

        );

    });


// =========================================================
// RESULT PANEL
// =========================================================

function showResultPanel() {

    if (emptyState) {

        emptyState.hidden =
            true;


        emptyState.classList.add(
            "hidden"
        );

    }


    if (resultContent) {

        resultContent.hidden =
            false;


        resultContent.classList.remove(
            "hidden"
        );

    }

}


// =========================================================
// RISK SCORE
// =========================================================

function renderRiskScore(result) {

    const score =
        getScore(result);


    const decision =

        String(

            result?.decision ||

            "ALLOW"

        ).toUpperCase();


    setText(

        scoreValue,

        `${score}/100`

    );


    setText(

        riskLabel,

        result?.risk_label ||

        result?.risk_level ||

        "Lower risk"

    );


    setText(

        decisionBadge,

        decision

    );


    if (decisionBadge) {

        decisionBadge.classList.remove(

            "review",

            "block"

        );


        if (decision === "REVIEW") {

            decisionBadge.classList.add(
                "review"
            );

        }


        if (decision === "BLOCK") {

            decisionBadge.classList.add(
                "block"
            );

        }

    }


    if (scoreMeter) {

        scoreMeter.style.width =
            `${score}%`;


        scoreMeter.setAttribute(

            "aria-valuenow",

            String(score)

        );


        scoreMeter.classList.remove(

            "review",

            "block"

        );


        if (decision === "REVIEW") {

            scoreMeter.classList.add(
                "review"
            );

        }


        if (decision === "BLOCK") {

            scoreMeter.classList.add(
                "block"
            );

        }

    }

}


// =========================================================
// RECIPIENT INTELLIGENCE
// =========================================================

function renderRecipientIntelligence(result) {

    const recipient =
        result?.recipient_intelligence || {};


    const score =
        Number(

            recipient.trust_score || 0

        );


    const level =
        recipient.trust_level ||
        "UNKNOWN";


    setText(

        trustScore,

        score

    );


    setText(

        trustLevel,

        level

    );


    setText(

        previousTransactions,

        recipient.previous_transactions || 0

    );


    if (trustMeter) {

        const width =

            Math.max(

                0,

                Math.min(
                    100,
                    score
                )

            );


        trustMeter.style.width =
            `${width}%`;


        trustMeter.classList.remove(

            "medium",

            "low"

        );


        if (score < 40) {

            trustMeter.classList.add(
                "low"
            );

        }

        else if (score < 70) {

            trustMeter.classList.add(
                "medium"
            );

        }

    }


    if (trustLevel) {

        trustLevel.classList.remove(

            "medium",

            "low"

        );


        if (score < 40) {

            trustLevel.classList.add(
                "low"
            );

        }

        else if (score < 70) {

            trustLevel.classList.add(
                "medium"
            );

        }

    }


    renderList(

        trustSignals,

        recipient.signals,

        "No recipient signals available."

    );

}


// =========================================================
// SCAM LANGUAGE / FRAUD MESSAGE
// =========================================================

function renderScamLanguage(result) {

    const scam =
        result?.scam_language || {};


    const detected =
        Boolean(
            scam.detected
        );


    if (detected) {

        setText(

            scamStatus,

            "DETECTED"

        );


        setText(

            scamDescription,

            "Suspicious fraud-message language was detected."

        );

    }

    else {

        setText(

            scamStatus,

            "CLEAR"

        );


        setText(

            scamDescription,

            "No configured suspicious fraud-message language was detected."

        );

    }


    if (scamStatus) {

        scamStatus.classList.remove(

            "safe",

            "detected"

        );


        scamStatus.classList.add(

            detected

                ? "detected"

                : "safe"

        );

    }


    if (!keywordContainer) {
        return;
    }


    keywordContainer.innerHTML = "";


    const keywords =

        Array.isArray(
            scam.keywords
        )

            ? scam.keywords

            : [];


    if (keywords.length === 0) {

        return;

    }


    keywords.forEach(keyword => {

        const tag =
            document.createElement(
                "span"
            );


        tag.className =
            "keyword-tag";


        tag.textContent =
            keyword;


        keywordContainer.appendChild(
            tag
        );

    });

}


// =========================================================
// BEHAVIORAL INTELLIGENCE
// =========================================================

function renderBehavioralIntelligence(result) {

    const behavior =
        result?.behavioral_intelligence || {};


    const available =
        behavior.available === true;


    const level =
        behavior.behavior_level ||
        "LEARNING";


    const deviation =
        Number(

            behavior.deviation_ratio || 1

        );


    const baseline =
        Number(

            behavior.baseline_amount ??

            behavior.median_amount ??

            0

        );


    const score =
        Number(

            behavior.behavior_score || 0

        );


    setText(

        behaviorLevel,

        level

    );


    setText(

        behaviorDeviation,

        available

            ? deviation.toFixed(1)

            : "—"

    );


    setText(

        behaviorBaseline,

        formatAmount(baseline)

    );


    setText(

        behaviorScore,

        score

    );


    if (behaviorLevel) {

        behaviorLevel.classList.remove(

            "low",

            "medium",

            "high"

        );


        const normalized =
            level.toLowerCase();


        if (normalized === "low") {

            behaviorLevel.classList.add(
                "low"
            );

        }


        if (normalized === "medium") {

            behaviorLevel.classList.add(
                "medium"
            );

        }


        if (normalized === "high") {

            behaviorLevel.classList.add(
                "high"
            );

        }

    }


    renderList(

        behaviorSignals,

        behavior.signals,

        "No behavioral signals available."

    );

}


// =========================================================
// LIST HELPER
// =========================================================

function renderList(
    container,
    items,
    fallback
) {

    if (!container) {
        return;
    }


    container.innerHTML = "";


    const values =

        Array.isArray(items)

            ? items

            : [];


    if (values.length === 0) {

        const item =
            document.createElement(
                "li"
            );


        item.textContent =
            fallback;


        container.appendChild(
            item
        );


        return;

    }


    values.forEach(value => {

        const item =
            document.createElement(
                "li"
            );


        item.textContent =
            value;


        container.appendChild(
            item
        );

    });

}


// =========================================================
// REASONS
// =========================================================

function renderReasons(result) {

    renderList(

        reasonList,

        result?.reasons,

        "No configured fraud warning signal was detected."

    );


    setText(

        adviceText,

        result?.advice || "—"

    );

}


// =========================================================
// FINAL RESULT
// =========================================================

function renderResult(result) {

    showResultPanel();


    renderRiskScore(
        result
    );


    renderRecipientIntelligence(
        result
    );


    renderScamLanguage(
        result
    );


    renderBehavioralIntelligence(
        result
    );


    renderReasons(
        result
    );


    showPage(
        "resultPage"
    );

}


// =========================================================
// FORM DATA
// =========================================================

function getFormData() {

    const paymentNote =

        noteInput?.value.trim() || "";


    const fraudMessage =

        fraudMessageInput?.value.trim() || "";


    /*
     * IMPORTANT:
     *
     * Your existing backend already analyzes the "note"
     * field for scam language.
     *
     * We combine the normal payment note and the new
     * fraud message here so the existing backend can
     * analyze the fraud message without changing app.py.
     */

    let combinedNote = "";


    if (paymentNote && fraudMessage) {

        combinedNote =
            `${paymentNote} ${fraudMessage}`;

    }

    else if (fraudMessage) {

        combinedNote =
            fraudMessage;

    }

    else {

        combinedNote =
            paymentNote;

    }


    return {

        amount:

            Number(
                amountInput?.value || 0
            ),


        payee:

            payeeInput?.value.trim() || "",


        upi_id:

            upiInput?.value.trim() || "",


        /*
         * Existing backend field.
         * Fraud message is included here for analysis.
         */

        note:
            combinedNote,


        /*
         * Also send fraud_message separately.
         * This does not break the existing backend.
         */

        fraud_message:
            fraudMessage,


        new_payee:

            Boolean(
                newPayeeInput?.checked
            )

    };

}


// =========================================================
// ANALYZE TRANSACTION
// =========================================================

if (analyzeForm) {

    analyzeForm.addEventListener(

        "submit",

        async event => {

            event.preventDefault();


            setText(

                formError,

                ""

            );


            const originalButtonText =

                analyzeButton

                    ? analyzeButton.textContent

                    : "";


            if (analyzeButton) {

                analyzeButton.disabled =
                    true;


                analyzeButton.textContent =
                    "Analyzing...";

            }


            openAnalysisOverlay();


            try {

                const animationPromise =

                    runAnalysisAnimation();


                const response =

                    await fetch(

                        "/api/analyze",

                        {

                            method: "POST",


                            headers: {

                                "Content-Type":
                                    "application/json"

                            },


                            body:

                                JSON.stringify(

                                    getFormData()

                                )

                        }

                    );


                const payload =

                    await response.json();


                if (

                    !response.ok ||

                    payload.ok === false

                ) {

                    throw new Error(

                        payload.error ||

                        "Unable to analyze transaction."

                    );

                }


                await animationPromise;


                closeAnalysisOverlay();


                renderResult(

                    payload.result

                );


                await loadTransactions();

            }


            catch (error) {

                closeAnalysisOverlay();


                console.error(
                    error
                );


                setText(

                    formError,

                    error.message ||

                    "Something went wrong."

                );

            }


            finally {

                if (analyzeButton) {

                    analyzeButton.disabled =
                        false;


                    analyzeButton.textContent =
                        originalButtonText;

                }

            }

        }

    );

}


// =========================================================
// HISTORY
// =========================================================

async function loadTransactions() {

    if (!transactionRows) {
        return;
    }


    try {

        const response =

            await fetch(

                "/api/transactions"

            );


        const payload =

            await response.json();


        if (!response.ok) {

            throw new Error(

                payload.error ||

                "Unable to load history."

            );

        }


        const items =

            Array.isArray(
                payload.transactions
            )

                ? payload.transactions

                : [];


        renderTransactionHistory(
            items
        );

    }


    catch (error) {

        console.error(
            error
        );


        transactionRows.innerHTML =

            `<tr>

                <td
                    colspan="6"
                    class="empty-row">

                    Unable to load transaction history.

                </td>

            </tr>`;


        updateStatistics([]);

    }

}


// =========================================================
// HISTORY RENDERING
// =========================================================

function renderTransactionHistory(items) {

    if (!transactionRows) {
        return;
    }


    transactionRows.innerHTML = "";


    if (items.length === 0) {

        transactionRows.innerHTML =

            `<tr>

                <td
                    colspan="6"
                    class="empty-row">

                    No transactions analyzed yet.

                </td>

            </tr>`;


        updateStatistics(
            items
        );


        return;

    }


    items.forEach(transaction => {

        const row =
            document.createElement(
                "tr"
            );


        const decision =

            String(

                transaction.decision ||

                "ALLOW"

            ).toUpperCase();


        const score =

            Number(

                transaction.risk_score ??

                transaction.score ??

                0

            );


        row.innerHTML = `

            <td>

                <strong>

                    ${escapeHtml(

                        transaction.payee ||

                        "Unknown"

                    )}

                </strong>

            </td>


            <td>

                ${escapeHtml(

                    transaction.upi_id ||

                    "—"

                )}

            </td>


            <td>

                ${formatAmount(

                    transaction.amount

                )}

            </td>


            <td>

                <strong>

                    ${score}/100

                </strong>

            </td>


            <td>

                <span

                    class="table-badge ${decision}">

                    ${decision}

                </span>

            </td>


            <td>

                ${escapeHtml(

                    formatTime(

                        transaction.created_at

                    )

                )}

            </td>

        `;


        transactionRows.appendChild(
            row
        );

    });


    updateStatistics(
        items
    );

}


// =========================================================
// STATISTICS
// =========================================================

function updateStatistics(items) {

    const reviews =

        items.filter(

            item =>

                String(

                    item.decision || ""

                ).toUpperCase() === "REVIEW"

        ).length;


    const blocks =

        items.filter(

            item =>

                String(

                    item.decision || ""

                ).toUpperCase() === "BLOCK"

        ).length;


    setText(

        totalCount,

        items.length

    );


    setText(

        reviewCount,

        reviews

    );


    setText(

        blockCount,

        blocks

    );

}


// =========================================================
// ESCAPE HTML
// =========================================================

function escapeHtml(value) {

    return String(

        value ?? ""

    )

        .replaceAll(

            "&",

            "&amp;"

        )

        .replaceAll(

            "<",

            "&lt;"

        )

        .replaceAll(

            ">",

            "&gt;"

        )

        .replaceAll(

            '"',

            "&quot;"

        )

        .replaceAll(

            "'",

            "&#039;"

        );

}


// =========================================================
// CLEAR HISTORY
// =========================================================

if (clearHistoryBtn) {

    clearHistoryBtn.addEventListener(

        "click",

        async () => {

            const confirmed =

                window.confirm(

                    "Are you sure you want to clear all ScamShield transaction history?"

                );


            if (!confirmed) {
                return;
            }


            const originalText =

                clearHistoryBtn.textContent;


            clearHistoryBtn.disabled =
                true;


            clearHistoryBtn.textContent =
                "Clearing...";


            try {

                const response =

                    await fetch(

                        "/api/transactions/clear",

                        {

                            method: "DELETE"

                        }

                    );


                const payload =

                    await response.json();


                if (

                    !response.ok ||

                    payload.ok === false

                ) {

                    throw new Error(

                        payload.error ||

                        "Unable to clear transaction history."

                    );

                }


                await loadTransactions();


                window.alert(

                    "Transaction history cleared successfully."

                );

            }


            catch (error) {

                console.error(
                    error
                );


                window.alert(

                    error.message ||

                    "Unable to clear transaction history."

                );

            }


            finally {

                clearHistoryBtn.disabled =
                    false;


                clearHistoryBtn.textContent =
                    originalText;

            }

        }

    );

}


// =========================================================
// START
// =========================================================

document.addEventListener(

    "DOMContentLoaded",

    () => {

        closeAnalysisOverlay();


        showPage(
            "homePage"
        );


        loadTransactions();

    }

);