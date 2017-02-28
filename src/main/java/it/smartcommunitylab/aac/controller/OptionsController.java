package it.smartcommunitylab.aac.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class OptionsController {

	@RequestMapping(value = "/**", method=RequestMethod.OPTIONS)
	public @ResponseBody HttpStatus options(HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.addHeader("Access-Control-Allow-Headers", "origin, content-type, accept, x-requested-with, authorization");
		response.addHeader("Access-Control-Allow-Methods", "GET, PUT, DELETE, POST, OPTIONS");
		response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin"));
		response.addHeader("Access-Control-Allow-Credentials", "true");

		return HttpStatus.OK;
	}
}
