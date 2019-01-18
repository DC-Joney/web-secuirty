### 流程类

- MethodSecurityMetadataSourceAdvisorRegistrar
- MethodSecurityMetadataSourceAdvisor
- MethodSecurityInterceptor


#### 权限认证

- AbstractSecurityInterceptor(beforeInvocation)
- AbstractMethodSecurityMetadataSource(getAttributes(object))
- DelegatingMethodSecurityMetadataSource(getAttributes(method,targetClass))

#### 实现类
GlobalMethodSecurityConfiguration 
 - methodSecurityInterceptor()
 - methodSecurityMetadataSource() 
 
### 流程
```

 AbstractSecurityInterceptor(针对web和method授权)   
    - methodSecurityInterceptor
    - FilterSecurityInterceptor
    
 SecurityMetadataSource（针对web和method元信息）
    - FilterInvocationSecurityMetadataSource
    - MethodSecurityMetadataSource

```

 methodSecurityInterceptor -> AbstractMethodSecurityMetadataSource
 
 FilterSecurityInterceptor -> FilterInvocationSecurityMetadataSource