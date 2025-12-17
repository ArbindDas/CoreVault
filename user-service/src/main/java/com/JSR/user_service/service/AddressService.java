
package com.JSR.user_service.service;

import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.entities.Address;
import com.JSR.user_service.entities.UserProfile;
import com.JSR.user_service.repository.AddressRepository;
import com.JSR.user_service.repository.UserProfileRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;


public interface AddressService {

    // adding the  Address
    AddressDTO addAddress(String authHeader, AddressDTO addressDTO);
    List<AddressDTO>getMyAddress(String authHeader);

}