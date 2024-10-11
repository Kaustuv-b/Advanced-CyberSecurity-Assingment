function checkPasswordStrength() {
    var password = document.getElementsByName("password")[0].value;
    var strengthMeter = document.getElementById("strength-meter");

    var hasUpperCase = /[A-Z]/.test(password);
    var hasNumber = /\d/.test(password);
    var hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    var hasMinLength = password.length >= 8; 

 
    document.getElementById("uppercase").classList.toggle("valid", hasUpperCase);
    document.getElementById("number").classList.toggle("valid", hasNumber);
    document.getElementById("special-char").classList.toggle("valid", hasSpecialChar);
    document.getElementById("min-length").classList.toggle("valid", hasMinLength);

    var strength = 0;
    if (hasUpperCase) strength += 1;
    if (hasNumber) strength += 1;
    if (hasSpecialChar) strength += 1;
    if (hasMinLength) strength += 1;

    
    if (strength === 1) {
      strengthMeter.firstElementChild.className = "weak";
    } else if (strength === 2) {
      strengthMeter.firstElementChild.className = "medium";
    } else if (strength === 3) {
      strengthMeter.firstElementChild.className = "strong";
    } else if (strength === 4) {
      strengthMeter.firstElementChild.className = "very-strong";
    } else {
      strengthMeter.firstElementChild.className = "";  
    }
}
