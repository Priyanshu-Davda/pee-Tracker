let userName = '';

function join() {
  const name = document.getElementById('nameInput').value.trim();
  if (!name) return alert('Enter a name!');
  fetch('/join', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name })
  }).then(res => res.json())
    .then(data => {
      userName = name;
      document.getElementById('username').textContent = name;
      document.getElementById('joinSection').style.display = 'none';
      document.getElementById('appSection').style.display = 'block';
      loadLeaderboard();
    });
}

function logPee() {
  fetch('/pee', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: userName })
  }).then(() => {
    loadLeaderboard();
  });
}

function loadLeaderboard() {
  fetch('/leaderboard')
    .then(res => res.json())
    .then(data => {
      const ul = document.getElementById('leaderboard');
      ul.innerHTML = '';
      data.forEach(user => {
        const li = document.createElement('li');
        li.textContent = `${user.name} - ${user.count} pees`;
        ul.appendChild(li);
      });
    });
}
