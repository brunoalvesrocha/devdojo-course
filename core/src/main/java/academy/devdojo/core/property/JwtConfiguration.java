package academy.devdojo.core.property;

import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties("jwt.config")
@Data
@ToString
public class JwtConfiguration {

    private String loginUrl = "/login/**";
    private int expiration=3600;
    private String privateKey = "xL0EVfRdsgI86UJJnu37jSvNWOkzu1Ax";
    private String type = "encrypted";
    @NestedConfigurationProperty
    private Header header = new Header();

    @Data
    public static class Header {
        private String name = "Authorization";
        private String prefix = "Bearer ";
    }
}
