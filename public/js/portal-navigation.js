(function () {
    const shell = document.querySelector(".portal-shell-page");
    const drawer = document.getElementById("portal-drawer");
    const navigation = drawer && drawer.querySelector(".sidebar-nav");
    const toggle = document.querySelector("[data-portal-menu-toggle]");
    const backdrop = document.querySelector("[data-portal-drawer-backdrop]");
    const adminControl = drawer && drawer.querySelector("[data-admin-control]");
    const adminControlToggle = adminControl && adminControl.querySelector("[data-admin-control-toggle]");

    if (!shell || !drawer || !navigation) return;

    const portalKey = drawer.dataset.portal || "portal";
    const scrollStorageKey = `everkind-sidebar-scroll:${portalKey}`;
    const activeLink = navigation.querySelector("a.active");

    try {
        const savedScroll = Number(sessionStorage.getItem(scrollStorageKey));
        if (Number.isFinite(savedScroll)) navigation.scrollTop = savedScroll;
    } catch (error) {
        console.error("Unable to restore sidebar position", error);
    }

    requestAnimationFrame(() => {
        if (!activeLink) return;
        const navRect = navigation.getBoundingClientRect();
        const activeRect = activeLink.getBoundingClientRect();
        if (activeRect.top < navRect.top || activeRect.bottom > navRect.bottom) {
            activeLink.scrollIntoView({ block: "nearest" });
        }
    });

    let scrollFrame = null;
    navigation.addEventListener("scroll", () => {
        if (scrollFrame) cancelAnimationFrame(scrollFrame);
        scrollFrame = requestAnimationFrame(() => {
            try {
                sessionStorage.setItem(scrollStorageKey, String(navigation.scrollTop));
            } catch (error) {
                console.error("Unable to save sidebar position", error);
            }
        });
    }, { passive: true });

    const closeAdminControl = () => {
        if (!adminControl || !adminControlToggle) return;
        adminControl.classList.remove("is-open");
        adminControlToggle.setAttribute("aria-expanded", "false");
    };

    const closeDrawer = () => {
        closeAdminControl();
        shell.classList.remove("portal-drawer-open");
        if (toggle) toggle.setAttribute("aria-expanded", "false");
        document.body.classList.remove("portal-drawer-lock");
    };

    if (adminControl && adminControlToggle) {
        adminControlToggle.addEventListener("click", () => {
            const opening = !adminControl.classList.contains("is-open");
            adminControl.classList.toggle("is-open", opening);
            adminControlToggle.setAttribute("aria-expanded", String(opening));
        });
        document.addEventListener("click", (event) => {
            if (!adminControl.contains(event.target)) closeAdminControl();
        });
    }

    if (toggle && backdrop) {
        toggle.addEventListener("click", () => {
            const opening = !shell.classList.contains("portal-drawer-open");
            shell.classList.toggle("portal-drawer-open", opening);
            toggle.setAttribute("aria-expanded", String(opening));
            document.body.classList.toggle("portal-drawer-lock", opening);
        });
        backdrop.addEventListener("click", closeDrawer);
        window.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && adminControl && adminControl.classList.contains("is-open")) {
                closeAdminControl();
                return;
            }
            if (event.key === "Escape") closeDrawer();
        });
        window.addEventListener("resize", () => {
            if (window.innerWidth > 1024) closeDrawer();
        });
    }

    drawer.querySelectorAll("[data-portal-nav-link]").forEach((link) => {
        link.addEventListener("click", () => {
            try {
                sessionStorage.setItem(scrollStorageKey, String(navigation.scrollTop));
            } catch (error) {
                console.error("Unable to save sidebar position", error);
            }
            closeDrawer();
        });
    });
}());
