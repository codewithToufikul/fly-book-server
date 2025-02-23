const saveMessage = async (messageData) => {
  try {
    const response = await axios.post(
      'http://localhost:5000/api/send-message',
      messageData,
      {
        headers: {
          'Authorization': `Bearer ${yourAuthToken}`
        }
      }
    );
    
    if (response.data.success) {
      // Handle successful message save
      console.log("Message saved successfully");
    }
  } catch (error) {
    console.error("Error saving message:", error);
  }
}; 