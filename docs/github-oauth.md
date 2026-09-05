# GitHub OAuth Setup Guide for LeakGuard

This guide outlines how to register and configure a GitHub OAuth Application to enable zero-credential, secure repository authentication and remediation in LeakGuard.

---

## 1. Create GitHub OAuth Application

1. Sign in to your GitHub account.
2. In the upper-right corner of any page, click your profile photo, then click **Settings**.
3. In the left sidebar, scroll down and click **Developer settings** (or visit directly: [https://github.com/settings/developers](https://github.com/settings/developers)).
4. Under **OAuth Apps**, click **New OAuth App** (or **Register a new application**).

---

## 2. Fill Application Details

Fill in the registration form with the following settings for your local development environment:

| Field | Recommended Value | Description |
| :--- | :--- | :--- |
| **Application name** | `LeakGuard Security Remediation` | Display name shown to users during authorization |
| **Homepage URL** | `http://localhost:8000` | The root URL where LeakGuard is running |
| **Application description** | `Automated Python AST static analysis & resource leak remediation` | Optional description |
| **Authorization callback URL** | `http://localhost:8000/api/github/callback` | The URL GitHub redirects to after authorization |

> **Note on Callback URLs**: LeakGuard also supports `http://localhost:8000/auth/github/callback`. Ensure the URL configured on GitHub exactly matches your local running port.

---

## 3. Generate Client Secret

1. After registering, you will see your **Client ID**.
2. Click **Generate a new client secret**.
3. You may be prompted to confirm your GitHub password or 2FA.
4. Immediately copy the generated **Client Secret** (GitHub will not display it again).

---

## 4. Configure Backend Environment

1. In the root directory of the LeakGuard project (`VH26-AlgoMinds`), create a `.env` file (you can copy `.env.example`):
   ```bash
   cp .env.example .env
   ```
2. Open `.env` in your editor and populate the variables:
   ```env
   GITHUB_CLIENT_ID=your_actual_client_id_here
   GITHUB_CLIENT_SECRET=your_actual_client_secret_here
   GITHUB_REDIRECT_URI=http://localhost:8000/api/github/callback
   ```
3. Save the `.env` file.

> 🔒 **Security Notice**:
> - Never commit `.env` or any files containing client secrets to Git.
> - Client secrets and access tokens remain strictly in backend memory on the server and are never sent to the browser or stored in `localStorage`.

---

## 5. Restart Backend Server

Restart the LeakGuard server so it loads the new configuration:

```bash
# Start server (loads .env automatically)
python app.py
```

---

## 6. Test OAuth Flow

1. Open your browser to [http://localhost:8000](http://localhost:8000).
2. Click **Connect GitHub** in the top navigation or Project Source card.
3. Click **[ 🐙 Authorize with GitHub ]**.
4. You will be redirected to GitHub's authorization page requesting permissions (`repo`, `read:user`).
5. Click **Authorize <your-app-name>**.
6. GitHub will redirect back to `http://localhost:8000/#github_connected=true`.
7. LeakGuard will display:
   - `✓ Authenticated as @username`
   - Real repository search and selection browser
   - Real branch selection
8. Select your repository and branch, then click **[ ⚡ Connect Repository ]** to download and immediately scan the codebase!
