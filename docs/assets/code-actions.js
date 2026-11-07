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
      const title = block.querySelector("th.filename, :scope > span.filename");
      const button = block.querySelector(".md-code__nav");
      if (title && button && !title.contains(button)) title.appendChild(button);
    });

    // A reference section keeps its shorter column in view beside the longer
    // one. Where the text runs past the code, the code stays: no taller than
    // the window, scrolling in its column when it is taller. Where the code
    // runs past the text, the text stays, when it fits in the window; text
    // and code both taller than the window scroll as one. In one column
    // (below 1440px) the classes change nothing.
    const sections = [...document.querySelectorAll(".md-typeset .tf-ref")]
      .map((section) => [section, section.querySelector(":scope > .tf-ref__text"), section.querySelector(":scope > .tf-ref__code")])
      .filter(([, text, code]) => text && code);
    if (sections.length) {
      let pending = false;
      const measure = () => {
        pending = false;
        const room = window.innerHeight - parseFloat(getComputedStyle(document.documentElement).fontSize) * 10.5;
        sections.forEach(([section, text, code]) => {
          const tall = text.getBoundingClientRect().height;
          section.classList.toggle("tf-ref--sticks", tall > code.scrollHeight);
          section.classList.toggle("tf-ref--text-sticks", tall <= code.scrollHeight && tall <= room);
        });
      };
      const later = () => {
        if (!pending) requestAnimationFrame(measure);
        pending = true;
      };
      const watch = new ResizeObserver(later);
      sections.forEach(([, text, code]) => {
        watch.observe(code);
        [...text.children].forEach((child) => watch.observe(child));
      });
      window.addEventListener("resize", later);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", enhanceDocs, { once: true });
  } else {
    enhanceDocs();
  }
})();
