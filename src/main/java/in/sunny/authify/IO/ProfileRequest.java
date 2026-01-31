package in.sunny.authify.IO;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ProfileRequest {

    @NotBlank(message = "Name should not be empty")
    private String name;

    @Email(message = "Enter valid email address")
    @NotNull(message = "Email should not be empty")
    private String email;

    @NotBlank(message = "Password should not be empty")
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;
}
