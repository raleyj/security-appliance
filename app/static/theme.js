/* Apply the saved choice before first paint; unavailable storage is harmless. */
(()=>{
 const key='security-appliance-theme';
 let theme='light';
 try{const saved=localStorage.getItem(key);if(saved==='dark'||saved==='light')theme=saved;}catch{}
 function apply(value){
  theme=value;document.documentElement.dataset.theme=value;
  document.querySelectorAll('[data-theme-toggle]').forEach(button=>{
   button.textContent=value==='dark'?'Light theme':'Dark theme';
   button.setAttribute('aria-label','Switch to '+(value==='dark'?'light':'dark')+' theme');
  });
 }
 apply(theme);
 document.addEventListener('DOMContentLoaded',()=>{
  apply(theme);
  document.querySelectorAll('[data-theme-toggle]').forEach(button=>button.addEventListener('click',()=>{
   apply(theme==='dark'?'light':'dark');try{localStorage.setItem(key,theme);}catch{}
  }));
 });
 window.addEventListener('storage',event=>{if(event.key===key)apply(event.newValue==='dark'?'dark':'light');});
})();
