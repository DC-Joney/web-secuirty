package com.security.starter.properties;

import com.security.starter.config.StoreType;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "spring.security.jwt")
public class JsonWebTokenProperties {

    private String[] permitUrls;

    private StoreType storeType;

    private String queryTokenParam;
}
