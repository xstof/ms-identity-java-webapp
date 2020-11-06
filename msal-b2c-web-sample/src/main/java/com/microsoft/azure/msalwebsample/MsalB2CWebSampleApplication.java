// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// package com.microsoft.azure.msalwebsample;

// import org.springframework.boot.SpringApplication;
// import org.springframework.boot.autoconfigure.SpringBootApplication;

// @SpringBootApplication
// public class MsalB2CWebSampleApplication {

// 	public static void main(String[] args) {
// 		SpringApplication.run(MsalB2CWebSampleApplication.class, args);
// 	}
// }

package com.microsoft.azure.msalwebsample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication
public class MsalB2CWebSampleApplication extends SpringBootServletInitializer {

 public static void main(String[] args) {
  SpringApplication.run(MsalB2CWebSampleApplication.class, args);
 }

 @Override
 protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
  return builder.sources(MsalB2CWebSampleApplication.class);
 }
}