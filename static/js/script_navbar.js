document.addEventListener('DOMContentLoaded', function() {
  const sidebarBtn = document.querySelector(".toggle-btn");
  const body = document.body;

  sidebarBtn.addEventListener("click", () => {
      body.classList.toggle("active");
  });
});
