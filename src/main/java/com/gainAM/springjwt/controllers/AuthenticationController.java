package com.gainAM.springjwt.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.gainAM.springjwt.repository.*;
import com.gainAM.springjwt.security.jwt.JwtUtils;
import com.gainAM.springjwt.security.services.UserDetailsImpl;
import com.gainAM.springjwt.model.ERole;
import com.gainAM.springjwt.model.Role;
import com.gainAM.springjwt.model.User;
import com.gainAM.springjwt.payload.request.*;
import com.gainAM.springjwt.payload.response.*;



@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("api/auth")
public class AuthenticationController {

	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	UserRepository userRepository;
	
	@Autowired
	RoleRepository roleRepository;
	
	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils  jwtUtils;
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);
		
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();		
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());

		return ResponseEntity.ok(new JwtResponse(jwt, 
												 userDetails.getId(), 
												 userDetails.getUsername(), 
												 userDetails.getEmail(), 
												 roles));
	}
	
	@PostMapping("signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(), 
							 signUpRequest.getEmail(),
							 encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		if (strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(ERole.ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);

					break;
				case "doctor":
					Role doctorRole = roleRepository.findByName(ERole.DOCTOR)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(doctorRole);

					break;
				case "accountant":
						Role accRole = roleRepository.findByName(ERole.ACCOUNTANT)
							.orElseThrow(()->new RuntimeException("Error: Role is not found."));
						roles.add(accRole);
					break;
					
				case "assistance":
						Role assistanceRole = roleRepository.findByName(ERole.DENTAL_ASSISTANCE)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found"));
						roles.add(assistanceRole);
					break;
				
				case "receptionist":
						Role receptionist = roleRepository.findByName(ERole.RECEPTIONIST)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found"));
						roles.add(receptionist);
					break;
				
				case "patient":
						Role patient = roleRepository.findByName(ERole.PATIENT)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found"));
						roles.add(patient);
					break;
					
				default:
					Role userRole = roleRepository.findByName(ERole.DENTAL_ASSISTANCE)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}
	

}
