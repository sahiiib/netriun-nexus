'use strict';
(() => {
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  const saved = localStorage.getItem('netriun-theme');
  let choice = ['system', 'dark', 'light'].includes(saved) ? saved : 'dark';

  const apply = () => {
    document.documentElement.dataset.theme = choice === 'system' ? (media.matches ? 'dark' : 'light') : choice;
    document.documentElement.dataset.themeChoice = choice;
    document.querySelectorAll('[data-theme-control]').forEach(select => { select.value = choice; });
  };

  apply();
  media.addEventListener('change', () => { if (choice === 'system') apply(); });
  document.addEventListener('DOMContentLoaded', () => {
    apply();
    document.querySelectorAll('[data-theme-control]').forEach(select => select.addEventListener('change', event => {
        choice = event.target.value;
        localStorage.setItem('netriun-theme', choice);
        apply();
      }));
  });
})();
