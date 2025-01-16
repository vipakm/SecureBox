namespace SecureBox.ViewModels
{
    public class LoginResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string Token { get; set; }
        public int? UserId { get; set; }
        public int Code { get; set; }
    }
}
