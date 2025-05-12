# cf-vps-monitor
[简体中文](https://github.com/kadidalax/cf-vps-monitor/blob/main/README.md) | [English](https://github.com/kadidalax/cf-vps-monitor/blob/main/README-EN.md)
## A VPS probe + website monitoring panel built with Cloudflare Workers.
Panel Demo: https://vps-monitor.abo-vendor289.workers.dev/

Frontend:

![image](https://github.com/user-attachments/assets/ff4e8ac1-eb33-4776-89ca-ee026df536f5)

Backend:

![image](https://github.com/user-attachments/assets/c63ede1c-2299-4d3e-9d2a-e5806dc6473b)

VPS Side:

![image](https://github.com/user-attachments/assets/d10a83f2-17c1-4523-8f79-03bb1ce77e1f)


# VPS Monitoring Panel (Cloudflare Worker + D1 Version) - Deployment Guide

This is a simple VPS monitoring panel deployed on Cloudflare Workers, using Cloudflare D1 database for data storage. This guide will walk you through deploying it using the Cloudflare **web console**, without needing command-line tools.

## Prerequisites

*   A Cloudflare account.

## Deployment Steps

### 1. Create D1 Database

You need a D1 database to store panel data (server list, API keys, monitoring data, etc.).

1.  Log in to the Cloudflare dashboard.
2.  In the left-hand menu, find and click `Storage & Databases`.
3.  In the dropdown menu, select `D1 SQL Database`.
4.  Click `Create database`.
5.  Name your database (e.g., `vps-monitor-db`), then click `Create`.
6.  **Important: Initialize Database Tables**
    *   After the database is created, you will see the database overview page. Click the `Console` tab.
    *   Copy the first SQL command below, paste it into the console's input box, and click `Execute`:
      ```sql
      CREATE TABLE IF NOT EXISTS admin_credentials (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL
      );
      ```
    *   Copy the second SQL command below, paste it, and click `Execute`:
      ```sql
      CREATE TABLE IF NOT EXISTS servers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        api_key TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        sort_order INTEGER
      );
      ```
    *   Copy the third SQL command below, paste it, and click `Execute`:
      ```sql
      CREATE TABLE IF NOT EXISTS metrics (
        server_id TEXT PRIMARY KEY,
        timestamp INTEGER,
        cpu TEXT,
        memory TEXT,
        disk TEXT,
        network TEXT,
        FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
      );
      ```

    *   Your database table structure is now ready.

### 2. Create and Configure Worker

Next, create the Worker and deploy the code.

1.  In the left-hand menu, click `Compute (Workers)`, then select `Workers & Pages`.
2.  On the overview page, click `Create application`.
3.  Select `Create Worker` and then `Hello World` template. Click `Deploy`.
4.  Name your Worker (e.g., `vps-monitor-worker`), ensuring the name is available.
5.  Click `Deploy`.
6.  After deployment, click `Edit code` to enter the Worker editor.
7.  **Delete all existing code in the editor**.
8.  Open the `worker.js` file from this repository and copy its **entire** content.
9.  Paste the copied code into the Cloudflare Worker editor.
10. Click the `Deploy` button in the upper right corner of the editor.

### 3. Bind D1 Database to Worker

The Worker needs to access the D1 database you created earlier.

1.  On the Worker's management page (click the Worker name above the code editor to return to the management page), select the `Settings` tab.
2.  On the settings page, select the `Bindings` submenu.
3.  Select `D1 database`.
4.  Enter `DB` (must be uppercase) for the `Variable name`.
5.  In the `D1 database` dropdown menu, select the database you created earlier (e.g., `vps-monitor-db`).
6.  Click `Save and deploy`. (Note: The original text says "Deploy", Cloudflare UI might vary slightly, "Save and deploy" or similar is common)

### 4. Set Trigger Frequency (for website checking)

1.  On the Worker's management page, select the `Settings` tab.
2.  On the settings page, select the `Triggers` submenu.
3.  Click `Add Cron Trigger`.
4.  Select `Schedule`. For the Worker execution frequency, choose `Hourly`, and enter `1` in the box below (i.e., check websites once every hour on the hour).
5.  Click `Add trigger`.

### 5. Access Panel

After deployment and binding, your monitoring panel should be accessible via the Worker's URL.

*   On the settings page, you will see a `.workers.dev` URL, for example, `vps-monitor.abo-vendor289.workers.dev`.
*   Open this URL in your browser, and you should see the frontend interface of the monitoring panel.

## Using the Panel

### 1. Initial Login

1.  Access your Worker URL.
2.  Click `Login` in the upper right corner of the page or directly access the `/login` path (e.g., `https://vps-monitor.abo-vendor289.workers.dev/login`).
3.  Log in with the default credentials:
    *   Username: `admin`
    *   Password: `admin`
4.  After logging in, it is recommended to change the password immediately.

### 2. Add Server

1.  After logging into the backend, you should see the management interface.
2.  Find the option to add a server.
3.  Enter the server's name and an optional description.
4.  Click `Save`.
5.  The panel will automatically generate a unique `Server ID` and `API Key`. **Please note down this Server ID and API Key**, as they will be needed when deploying the Agent.

### 3. Deploy Agent (Probe)

The Agent is a script that needs to run on your VPS to collect status information and send it back to the panel.

Download the script and run it:
```bash
wget https://raw.githubusercontent.com/kadidalax/cf-vps-monitor/main/cf-vps-monitor.sh -O cf-vps-monitor.sh && chmod +x cf-vps-monitor.sh && ./cf-vps-monitor.sh
```
Or:
```bash
curl -O https://raw.githubusercontent.com/kadidalax/cf-vps-monitor/main/cf-vps-monitor.sh && chmod +x cf-vps-monitor.sh && ./cf-vps-monitor.sh
```
*   Installation requires `API Key`, `Server ID`, and your `Worker URL`.
*   You can click `View Key` in the backend to get these three parameters.
*   Follow the prompts to enter the information. After installation, the Agent will start sending data to your panel periodically (every 60s). You should see the status updates for the corresponding server on the panel.

### 4. Agent Management

The installation script itself also provides management functions:

*   **Install Service:**
*   **Uninstall Service:**
*   **Check Status:**
*   **View Logs:**
*   **Stop Service:**
*   **Restart Service:**
*   **Modify Configuration:**

### 5. Add Monitored Website

1.  After logging into the backend, you should see the management interface.
2.  Click `Add Monitored Website`.
3.  Enter `Website Name (optional)` and `Website URL (e.g., https://example.com)`.
4.  Click `Save`.

### 6. Configure Telegram Notifications

1.  Create a bot with BotFather and get the `Bot Token`.
2.  Get your `ID` from `@userinfobot`.
3.  Fill in the above two items respectively.
4.  Enable notifications and click `Save Telegram Settings`.

## Notes

*   **Worker and D1 Daily Quotas:** Cloudflare Worker and D1 free tiers have limits. Please refer to the Cloudflare documentation for details.
*   **Security:** The default password `admin` is very insecure. Be sure to change it after the first login. The API key used by the Agent should also be kept safe.
*   **Error Handling:** If the panel or Agent encounters problems, you can check the Worker's logs (on the Cloudflare dashboard Worker page) and the Agent's logs.
*   All the above content and code are AI-generated. If you encounter any problems, please take the code directly to an AI.
