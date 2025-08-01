// Check login status when the page loads
window.onload = function() {
    fetch('/session')
        .then(res => res.json())
        .then(data => {
            if (data.loggedIn) {
                showApp(data.name);
            } else {
                showAuth();
            }
        });
};


function toggleAuthForms() {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    loginForm.style.display = loginForm.style.display === 'none' ? 'block' : 'none';
    registerForm.style.display = registerForm.style.display === 'none' ? 'block' : 'none';
}

function register() {
    const name = document.getElementById('registerName').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value.trim();

    if (!name || !email || !password) return alert('Please fill all fields!');

    fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name,
                email,
                password
            })
        }).then(res => {
            if (!res.ok) {
                return res.text().then(text => {
                    throw new Error(text)
                });
            }
            return res.json();
        })
        .then(data => {
            showApp(data.name);
        })
        .catch(err => {
            alert('Registration failed: ' + err.message);
        });
}

function login() {
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value.trim();
    if (!email || !password) return alert('Please enter email and password!');

    fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email,
                password
            })
        }).then(res => {
            if (!res.ok) {
                return res.text().then(text => {
                    throw new Error(text)
                });
            }
            return res.json();
        })
        .then(data => {
            showApp(data.name);
        })
        .catch(err => {
            alert('Login failed: ' + err.message);
        });
}

function logout() {
    fetch('/logout', {
        method: 'POST'
    }).then(() => {
        showAuth();
    });
}

function logPee() {
    fetch('/pee', {
        method: 'POST'
    }).then(res => {
        if (!res.ok) {
            alert('Something went wrong. You may be logged out.');
            showAuth();
        } else {
            loadLeaderboard();
        }
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

// UI transition functions
function showApp(name) {
    document.getElementById('username').textContent = name;
    document.getElementById('authSection').style.display = 'none';
    document.getElementById('appSection').style.display = 'block';
    loadLeaderboard();
}

function showAuth() {
    document.getElementById('authSection').style.display = 'block';
    document.getElementById('appSection').style.display = 'none';
}