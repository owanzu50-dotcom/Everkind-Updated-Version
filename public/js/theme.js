(function () {
    const storageKey = "everkind-portal-theme";
    const root = document.documentElement;

    const getTheme = () => {
        try {
            return localStorage.getItem(storageKey) === "dark" ? "dark" : "light";
        } catch (error) {
            return "light";
        }
    };

    const applyTheme = (theme) => {
        const nextTheme = theme === "dark" ? "dark" : "light";
        root.dataset.theme = nextTheme;
        root.style.colorScheme = nextTheme;
        document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
            const dark = nextTheme === "dark";
            button.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
            button.setAttribute("aria-pressed", String(dark));
            const icon = button.querySelector("[data-theme-icon]");
            const label = button.querySelector("[data-theme-label]");
            if (icon) icon.textContent = dark ? "☀" : "☾";
            if (label) label.textContent = dark ? "Light mode" : "Dark mode";
        });
    };

    applyTheme(getTheme());

    document.addEventListener("click", (event) => {
        const toggle = event.target.closest("[data-theme-toggle]");
        if (!toggle) return;
        const nextTheme = root.dataset.theme === "dark" ? "light" : "dark";
        try {
            localStorage.setItem(storageKey, nextTheme);
        } catch (error) {
            console.error("Unable to save theme preference", error);
        }
        applyTheme(nextTheme);
    });

    document.addEventListener("DOMContentLoaded", () => applyTheme(getTheme()));
}());
