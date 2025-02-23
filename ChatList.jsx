import axios from 'axios';

const fetchChatUsers = async () => {
  try {
    const token = localStorage.getItem('token'); // Or however you store your token
    const response = await axios.get('/api/chat-users', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    setChatUsers(response.data.users);
  } catch (error) {
    console.error('Error fetching chat users:', error);
  }
}; 