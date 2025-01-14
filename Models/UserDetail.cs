using System;
using System.Collections.Generic;

namespace SecureBox.Models;

public partial class UserDetail
{
    public int Sno { get; set; }

    public int? UserId { get; set; }

    public string UserName { get; set; } = null!;

    public string UserMailId { get; set; } = null!;

    public long? UserPhoneNo { get; set; }

    public string UserPassword { get; set; } = null!;

    public bool? UserStatus { get; set; }
}
