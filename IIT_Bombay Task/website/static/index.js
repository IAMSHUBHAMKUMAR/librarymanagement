function delete_account(token_data) {
    fetch("/delete_account", {
      method: "POST",
      body:  token_data,
    }).then((_res) => {
      window.location.href = "/login";
    });
  }