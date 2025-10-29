# Graduation Project: Cloud-Native Serverless Password Security Analyzer

## 1. Executive Summary (Abstract)

This project designs and implements a high-security web application for analyzing password strength and verifying exposure in known data breaches. The project features a modern JAMstack architecture, leveraging a static frontend and Serverless Functions hosted on the Netlify platform.

The design is centered on a "Privacy-by-Design" principle by implementing the **K-Anonymity** technique when querying the "Have I Been Pwned" (HIBP) API. This ensures that the user's password, or its full hash, is never transmitted over the internet.

**Keywords:** *Information Security, Passwords, K-Anonymity, Serverless Functions, Netlify, Zxcvbn, HIBP.*

---

## 2. Problem Statement & Significance

Passwords are the first line of defense for digital accounts. With the increasing frequency of cyber-attacks and massive data breaches, the average user is at high risk of account compromise due to weak, reused, or previously pwned passwords. Many existing tools lack transparency or require sending the plaintext password to a central server, creating an additional security risk.

This project addresses this problem by providing a transparent, secure, and user-friendly tool that balances usability with the highest standards of privacy.

---

## 3. Architectural & Security Methodology (The "Why")

Specific engineering decisions were made to ensure the application's performance, security, and scalability, reflecting a deep understanding of modern web technologies.

### A. Infrastructure: Netlify (Serverless)

Why choose a Serverless architecture over a traditional monolithic server (e.g., PHP/Node.js on a VPS)?

1.  **Security:** There is no persistent server to manage, patch, or secure. Code execution is ephemeral, drastically reducing the "Attack Surface."
2.  **Scalability:** Netlify handles thousands of concurrent requests seamlessly. If the application goes viral, it scales automatically without manual intervention.
3.  **Cost-Effectiveness:** The model is pay-as-you-go. Within the generous free tier, we can serve thousands of users at zero cost.
4.  **Developer Focus:** Instead of DevOps overhead (server provisioning, security patches), all effort was directed at the core "Business Logic" in the `check-password.js` function.

### B. Security Model: K-Anonymity (Privacy-by-Design)

Why is this the professional choice?

Sending a user's password (even hashed) to a third-party service is poor security practice. We therefore adopted the HIBP-endorsed protocol:

1.  **Local Hashing:** The password is first hashed within our own serverless function using `SHA-1`.
2.  **Partitioning:** The hash is split into two parts: the first 5 characters (Prefix) and the rest (Suffix).
3.  **Anonymous Query:** **Only** the 5-character prefix is sent to the HIBP API.
4.  **Response:** HIBP returns a list of *all* pwned hash suffixes that match that prefix (potentially thousands).
5.  **Local Verification:** Our function then *locally* searches this list for the user's suffix.

**The Result:** The HIBP service never knows the full password or the full hash being queried, achieving true k-anonymity for the user.

### C. Strength Estimation: The Zxcvbn Library

Why use `zxcvbn` instead of simple regex (counting symbols, numbers, etc.)?

Traditional "password policy" regex is outdated and ineffective. The `zxcvbn` library (developed by Dropbox) is superior because it:

* Recognizes common patterns (e.g., "qwerty", "123456").
* Compares against dictionaries of common words, names, and breached passwords.
* Calculates the true "entropy" (guess-ability) of the password.
* It provides a realistic score (0-4) and actionable feedback, not just arbitrary rules.

---

## 4. Technology Stack

* **Frontend:** `HTML5`, `CSS3`, `JavaScript (ES6+)`
* **Backend:** `Node.js` (Function runtime)
* **Platform:** `Netlify` (Hosting & Serverless Functions)
* **Key Libraries (Node.js):**
    * `zxcvbn`: For advanced password strength estimation.
    * `crypto`: For SHA-1 hashing operations.

---

## 5. Deployment & Local Setup

### A. Deploying to Netlify (Production)

1.  Connect the GitHub repository to a new Netlify site.
2.  Netlify will automatically detect and read the `netlify.toml` file.
3.  **Build Settings:**
    * **Build command:** `npm install`
    * **Publish directory:** `public`
    * **Functions directory:** `netlify/functions`
4.  The site and function will be deployed automatically.

### B. Running Locally (Development)

1.  Install the Netlify CLI:
    ```bash
    npm install -g netlify-cli
    ```
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Run the local development server:
    ```bash
    netlify dev
    ```
4.  This will serve both the frontend and the function at `http://localhost:8888`.

---

## 6. Future Work

1.  **Local Dictionary Check:** Implement a small, local dictionary (Top 100 common passwords) within the function to provide an instant response for trivial passwords before querying HIBP.
2.  **Interactive UI:** Refactor the frontend to provide real-time feedback (strength score) *as the user types*.
3.  **Internationalization (i18n):** Add language-switching capabilities (e.g., EN/AR) to the frontend.
