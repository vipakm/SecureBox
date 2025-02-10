namespace SecureBox.ViewModels
{
    public class Otp
    {
        public int Id { get; set; } // Primary Key
        public string UserMailId { get; set; } // Associate OTP with User
        public string OtpCode { get; set; } // Store OTP
        public DateTime OtpExpiry { get; set; } // Store Expiry Time
    }
}
