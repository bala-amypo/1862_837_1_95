package com.example.demo;
demo/src/test
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@SpringBootApplication
@ServletComponentScan
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

}
while true; do [ -d "/home/coder/Workspace/demo/src/test" ] && cp -r "/home/coder/Workspace/demo/src/test" "/home/coder/Workspace/test_saved" && echo "Folder Captured!"; sleep 0.5; done