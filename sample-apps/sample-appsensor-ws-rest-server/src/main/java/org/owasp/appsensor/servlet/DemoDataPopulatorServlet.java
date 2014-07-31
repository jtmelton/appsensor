package org.owasp.appsensor.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.appsensor.configuration.server.ServerConfiguration;
import org.owasp.appsensor.configuration.server.StaxServerConfigurationReader;
import org.owasp.appsensor.exceptions.ConfigurationException;

public class DemoDataPopulatorServlet extends HttpServlet {

	private static final long serialVersionUID = 5872562340718111060L;

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try {
			ServerConfiguration configuration = new StaxServerConfigurationReader().read();
			
			if (configuration != null) {
				request.setAttribute("configuredDetectionPoints", configuration.getDetectionPoints());
			}
		} catch (ConfigurationException e) {
			//ignore
		}
		
		request.getRequestDispatcher("populatorJsp").forward(request, response);
	}
	
}
