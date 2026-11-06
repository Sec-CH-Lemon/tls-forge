(() => {
  function enhanceDocs() {
    document.querySelectorAll(".tf-feature-code").forEach((panel) => {
      const header = panel.querySelector(".tf-feature-code__head");
      const action = panel.querySelector("pre > .md-code__nav");
      if (header && action) header.appendChild(action);
    });

    document.querySelectorAll(".md-typeset code").forEach((code) => {
      if (code.closest("pre") || code.textContent.length > 24) return;
      code.classList.add("tf-code-unbroken");
    });

    document.querySelectorAll(".md-typeset table:not([class])").forEach((table) => {
      const labels = [...table.querySelectorAll("thead th")].map((cell) => cell.textContent.trim().replace(/\s+/g, " "));
      const rows = [...table.querySelectorAll("tbody tr")];
      if (labels.length < 2 || labels.length > 3 || !rows.length || rows.some((row) => row.cells.length !== labels.length)) return;
      table.dataset.tfResponsive = "true";
      rows.forEach((row) => [...row.cells].forEach((cell, index) => {
        cell.dataset.tfLabel = labels[index];
      }));
    });

    document.querySelectorAll(".md-typeset .tabbed-set").forEach((set) => {
      const labels = set.querySelector(".tabbed-labels");
      const content = set.querySelector(".tabbed-content");
      if (!labels || !content || labels.querySelector(".tf-code-actions")) return;

      const blocks = [...content.children].filter((child) => child.classList.contains("tabbed-block"));
      const radios = [...set.children].filter((child) => child.matches('input[type="radio"]'));
      const actions = document.createElement("div");
      actions.className = "tf-code-actions";

      blocks.forEach((block, index) => {
        const button = block.querySelector(".md-code__nav");
        if (!button) return;
        button.dataset.tabIndex = String(index);
        actions.appendChild(button);
      });
      if (!actions.children.length) return;
      labels.appendChild(actions);

      const sync = () => {
        const selected = radios.findIndex((radio) => radio.checked);
        [...actions.children].forEach((action) => {
          action.hidden = Number(action.dataset.tabIndex) !== selected;
        });
      };
      set.addEventListener("change", sync);
      sync();
    });

    document.querySelectorAll(".md-typeset .highlight").forEach((block) => {
      if (block.closest(".tabbed-set")) return;
      const title = block.querySelector("th.filename");
      const button = block.querySelector(".md-code__nav");
      if (title && button && !title.contains(button)) title.appendChild(button);
    });

  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", enhanceDocs, { once: true });
  } else {
    enhanceDocs();
  }
})();
