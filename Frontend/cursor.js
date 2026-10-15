(() => {
  const supportsCustomCursor = window.matchMedia(
    '(pointer: fine) and (prefers-reduced-motion: no-preference)'
  );
  if (!supportsCustomCursor.matches) return;

  document.body.classList.add('has-tech-cursor');
  const cursor = document.createElement('div');
  cursor.className = 'tech-cursor';
  cursor.setAttribute('aria-hidden', 'true');
  cursor.innerHTML = `
    <span class="tech-cursor__ring"></span>
    <span class="tech-cursor__dot"></span>`;
  document.body.append(cursor);

  let x = -100;
  let y = -100;
  let targetX = x;
  let targetY = y;
  let animationFrame = 0;

  const animate = () => {
    x += (targetX - x) * 0.28;
    y += (targetY - y) * 0.28;
    cursor.style.setProperty('--cursor-x', `${x}px`);
    cursor.style.setProperty('--cursor-y', `${y}px`);
    if (Math.abs(targetX - x) + Math.abs(targetY - y) > 0.1) {
      animationFrame = requestAnimationFrame(animate);
    } else {
      animationFrame = 0;
    }
  };

  document.addEventListener('pointermove', (event) => {
    targetX = event.clientX;
    targetY = event.clientY;
    cursor.classList.add('is-visible');
    const target = event.target instanceof Element ? event.target : event.target.parentElement;
    cursor.classList.toggle(
      'is-hovering',
      Boolean(target?.closest('a,button,input,textarea,select,[role="button"]'))
    );
    if (!animationFrame) animationFrame = requestAnimationFrame(animate);
  });

  document.addEventListener('pointerdown', () => cursor.classList.add('is-pressed'));
  document.addEventListener('pointerup', () => cursor.classList.remove('is-pressed'));
  document.addEventListener('pointerleave', (event) => {
    if (!event.relatedTarget) cursor.classList.remove('is-visible', 'is-hovering', 'is-pressed');
  });
})();
