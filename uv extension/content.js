// content.js — AI-Shield content script
// Runs inside the actual webpage. Listens for verdict messages from
// background.js and injects a visible warning banner when a page is
// flagged SUSPICIOUS or FRAUD.

const BANNER_ID = "ai-shield-banner";

function removeExistingBanner() {
    const existing = document.getElementById(BANNER_ID);
    if (existing) existing.remove();
}

function buildBanner({ verdict, confidence, reasons }) {
    const isFraud = verdict === "FRAUD";

    const banner = document.createElement("div");
    banner.id = BANNER_ID;

    // Inline styles so the banner doesn't depend on (or get overridden by)
    // the host page's CSS, and renders above everything else on the page.
    Object.assign(banner.style, {
        position: "fixed",
        top: "0",
        left: "0",
        right: "0",
        zIndex: "2147483647", // max z-index, sits above page content
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "12px",
        padding: "14px 20px",
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
        fontSize: "14px",
        lineHeight: "1.4",
        color: "#ffffff",
        backgroundColor: isFraud ? "#c0152f" : "#c77700",
        boxShadow: "0 2px 8px rgba(0,0,0,0.3)"
    });

    const textWrap = document.createElement("div");
    textWrap.style.display = "flex";
    textWrap.style.flexDirection = "column";
    textWrap.style.gap = "2px";

    const title = document.createElement("strong");
    title.textContent = isFraud
        ? "⚠ AI-Shield: This site looks fraudulent"
        : "⚠ AI-Shield: This site looks suspicious";
    title.style.fontSize = "15px";

    const detail = document.createElement("span");
    const pct = Math.round((confidence || 0) * 100);
    const reasonText = (reasons && reasons.length)
        ? reasons.slice(0, 3).join(" · ")
        : "No specific reasons returned.";
    detail.textContent = `Confidence: ${pct}%  —  ${reasonText}`;
    detail.style.opacity = "0.9";
    detail.style.fontSize = "12px";

    textWrap.appendChild(title);
    textWrap.appendChild(detail);

    const actions = document.createElement("div");
    actions.style.display = "flex";
    actions.style.gap = "8px";
    actions.style.flexShrink = "0";

    const leaveBtn = document.createElement("button");
    leaveBtn.textContent = "Leave this site";
    styleButton(leaveBtn, { filled: true });
    leaveBtn.addEventListener("click", () => {
        // Send the user somewhere safe rather than just closing the banner.
        window.location.href = "https://www.google.com/search?q=is+this+site+safe";
    });

    const dismissBtn = document.createElement("button");
    dismissBtn.textContent = "Dismiss";
    styleButton(dismissBtn, { filled: false });
    dismissBtn.addEventListener("click", () => banner.remove());

    actions.appendChild(leaveBtn);
    actions.appendChild(dismissBtn);

    banner.appendChild(textWrap);
    banner.appendChild(actions);

    return banner;
}

function styleButton(btn, { filled }) {
    Object.assign(btn.style, {
        cursor: "pointer",
        border: "1px solid rgba(255,255,255,0.8)",
        borderRadius: "4px",
        padding: "6px 12px",
        fontSize: "13px",
        fontWeight: "600",
        background: filled ? "#ffffff" : "transparent",
        color: filled ? "#000000" : "#ffffff"
    });
}

function showBanner(payload) {
    removeExistingBanner();

    // Wait for <body> if the script runs before it exists (document_start).
    const inject = () => document.body.appendChild(buildBanner(payload));

    if (document.body) {
        inject();
    } else {
        document.addEventListener("DOMContentLoaded", inject, { once: true });
    }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type !== "AI_SHIELD_VERDICT") return;

    showBanner({
        verdict: message.verdict,
        confidence: message.confidence,
        reasons: message.reasons
    });

    // Acknowledge receipt so background.js's sendMessage promise resolves cleanly.
    sendResponse({ received: true });
});