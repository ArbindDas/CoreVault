package com.JSR.user_service.service.serviceImpl;

import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.repository.AddressRepository;
import com.JSR.user_service.service.AddressService;
import com.JSR.user_service.utils.JwtUtil;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AddressServiceImpl implements AddressService {



    private final AddressRepository addressRepository;
    private final JwtUtil jwtUtil;

    public AddressServiceImpl(AddressRepository addressRepository, JwtUtil jwtUtil) {
        this.addressRepository = addressRepository;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public AddressDTO addAddress(String authHeader, AddressDTO addressDTO) {
        return null;
    }

    @Override
    public List<AddressDTO> getMyAddress(String authHeader) {
        return List.of();
    }
}
