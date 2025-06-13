document.getElementById('role').addEventListener('change', function() {
  const role = this.value;
  document.getElementById('emailField').style.display = role === 'teacher' ? 'block' : 'none';
  document.getElementById('studentIdField').style.display = role === 'student' ? 'block' : 'none';
});

document.getElementById('registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const role = document.getElementById('role').value;
  const email = document.getElementById('email').value;
  const studentId = document.getElementById('studentId').value;
  const password = document.getElementById('password').value;

  try {
    const response = await fetch('http://localhost:3000/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, student_id: studentId, password, role })
    });

    const data = await response.json();
    document.getElementById('message').textContent = 
      data.error ? `Error: ${data.error}` : 'Registration successful!';
  } catch (err) {
    document.getElementById('message').textContent = 'Failed to connect to server';
  }
});