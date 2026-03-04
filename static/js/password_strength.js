function scorePassword(pw) {
  let score = 0;
  if (!pw) return 0;
  if (pw.length >= 10) score++;
  if (/[a-z]/.test(pw)) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return score;
}

document.addEventListener("DOMContentLoaded", () => {
  const pw = document.querySelector('input[name="new_password"]');
  if (!pw) return;

  const help = document.createElement("p");
  help.className = "help";
  help.id = "pw-strength";
  pw.parentElement.parentElement.appendChild(help);

  pw.addEventListener("input", () => {
    const s = scorePassword(pw.value);
    help.textContent = `Password strength: ${s}/5`;
  });
});