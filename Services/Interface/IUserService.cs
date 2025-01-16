using SecureBox.Models;
using SecureBox.ViewModels;

namespace SecureBox.Services.Interface
{
    public interface IUserService
    {
        // Register User
        Task<string> RegisterAsync(string userName, string userMailId, long? userPhoneNo, string userPassword);

        // Login User
        Task<LoginResult> LoginAsync(string email, string password); // Updated return type

        // Reset Password (Send OTP)
        Task<string> ResetPasswordAsync(string email);

        // Generate JWT Token
        string GenerateJwtToken(UserDetail user);

        // Verify OTP
        bool VerifyOtp(string userOtp);
        Task<string> VerifyOtpAsync(string userMailId, string inputOtp);
        Task<string> UpdatePasswordAsync(string userMailId, string newPassword);
    }
}
