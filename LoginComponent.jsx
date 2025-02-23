const handleLogin = async (loginData) => {
  try {
    const response = await axios.post('/users/login', loginData);
    const { token } = response.data;
    localStorage.setItem('token', token); // Store token after successful login
  } catch (error) {
    console.error('Login error:', error);
  }
}; 