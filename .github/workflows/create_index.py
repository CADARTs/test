print("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerabilities Check</title>
  <!-- Bootstrap CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
  <!-- Bootstrap Icons CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css" rel="stylesheet">
  <style>
    /* Custom CSS for centering the buttons */
    .centered-btns {
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      height: 100vh; /* Adjust this value to change vertical centering */
    }
    /* Additional styling for spacing between buttons */
    .btn-group {
      margin-bottom: 10px; /* Adjust as needed */
    }
  </style>
</head>
<body>

<div class="centered-btns">
  <h1 class="mb-4">Vulnerabilities Check</h1>
  
  <!-- Button group with bug icon -->
  <div class="btn-group">
    <a href="issues.html" class="btn btn-primary">
      <i class="bi bi-bug me-2"></i> Go to Issues
    </a>
  </div>
  
  <!-- Button group with dependencies icon -->
  <div class="btn-group">
    <a href="dependencies.html" class="btn btn-primary">
      <i class="bi bi-box-seam me-2"></i> Go to Dependencies
    </a>
  </div>
</div>

<!-- Bootstrap JS (Optional, only if you need Bootstrap JavaScript features) -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""")