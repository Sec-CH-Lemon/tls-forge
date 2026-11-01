(() => {
  const layers = [...document.querySelectorAll('[data-parallax]')];
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  if (!layers.length) return;

  let framePending = false;
  const update = () => {
    framePending = false;
    if (reducedMotion.matches) return;

    const viewportMiddle = innerHeight / 2;
    for (const layer of layers) {
      const section = layer.closest('section');
      const bounds = section.getBoundingClientRect();
      if (bounds.bottom < -150 || bounds.top > innerHeight + 150) continue;

      const distance = viewportMiddle - (bounds.top + bounds.height / 2);
      const depth = Number(layer.dataset.parallax);
      const shift = Math.max(-90, Math.min(90, distance / innerHeight * depth));
      layer.style.setProperty('--parallax-y', shift.toFixed(1) + 'px');
    }
  };
  const schedule = () => {
    if (framePending || reducedMotion.matches) return;
    framePending = true;
    requestAnimationFrame(update);
  };

  addEventListener('scroll', schedule, {passive: true});
  addEventListener('resize', schedule, {passive: true});
})();
