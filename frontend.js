const deleteMessage = async (messageId) => {
  try {
    const response = await fetch(`/messages/${messageId}`, {
      method: 'DELETE',
    });
    
    if (!response.ok) {
      throw new Error('Failed to delete message');
    }

    // Remove the message from DOM immediately after successful deletion
    const messageElement = document.getElementById(`message-${messageId}`);
    if (messageElement) {
      messageElement.remove();
    }
  } catch (error) {
    console.error('Error:', error);
  }
}; 