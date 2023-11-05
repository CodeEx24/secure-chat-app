const notyf = new Notyf({
  duration: 5000,
  position: {
    x: 'right',
    y: 'top',
  },
  types: [
    {
      type: 'success',
      background: '#202426', // Custom background color for success notifications (e.g., green)
      duration: 5000,
      dismissible: true,
    },
    {
      type: 'error',
      background: '#202426', // Custom background color for error notifications (e.g., orange)
      duration: 5000,
      dismissible: true,
    },
  ],
});
