document.addEventListener("DOMContentLoaded", async () => {
    const statusEl = document.getElementById("connection-status");
    const summaryEl = document.getElementById("dashboard-summary");
    const taskListEl = document.getElementById("task-list");
    const updatedEl = document.getElementById("dashboard-updated");

    if (!statusEl) {
        return;
    }

    const renderDashboard = (data) => {
        if (!summaryEl || !taskListEl || !updatedEl) {
            return;
        }

        const summaryCards = [
            { label: "Active patients", value: data.summary.activePatients },
            { label: "Carers on shift", value: data.summary.carersOnShift },
            { label: "Tasks due today", value: data.summary.tasksDueToday },
            { label: "Urgent alerts", value: data.summary.urgentAlerts },
        ];

        summaryEl.innerHTML = summaryCards.map((card) => `
            <div class="metric-card">
                <span class="metric-label">${card.label}</span>
                <strong class="metric-value">${card.value}</strong>
            </div>
        `).join("");

        taskListEl.innerHTML = data.tasks.map((task) => `
            <li class="task-item">
                <div>
                    <div class="task-client">${task.client}</div>
                    <div class="task-name">${task.task}</div>
                </div>
                <div class="task-meta">
                    <span class="task-time">${task.time}</span>
                    <span class="priority priority-${task.priority.toLowerCase()}">${task.priority}</span>
                </div>
            </li>
        `).join("");

        const timestamp = new Date(data.lastUpdated).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
        });
        updatedEl.textContent = `Updated ${timestamp}`;
    };

    try {
        const healthResponse = await fetch("/api/health");
        const healthData = await healthResponse.json();

        if (!healthResponse.ok) {
            throw new Error(healthData.message || `HTTP ${healthResponse.status}`);
        }

        statusEl.textContent = `Connected: ${healthData.status} | Database: ${healthData.database}`;
        statusEl.classList.add("success");

        const dashboardResponse = await fetch("/api/dashboard");
        const dashboardData = await dashboardResponse.json();

        if (!dashboardResponse.ok) {
            throw new Error(dashboardData.message || `HTTP ${dashboardResponse.status}`);
        }

        renderDashboard(dashboardData);
    } catch (error) {
        statusEl.textContent = `Connection failed: ${error.message}`;
        statusEl.classList.add("error");

        if (summaryEl) {
            summaryEl.innerHTML = '<div class="metric-card error-card"><span class="metric-label">Dashboard</span><strong class="metric-value">Unavailable</strong></div>';
        }

        if (taskListEl) {
            taskListEl.innerHTML = '<li class="task-item empty-state">Unable to load care tasks right now.</li>';
        }

        if (updatedEl) {
            updatedEl.textContent = "Refresh to retry";
        }
    }
});
