package com.JSR.user_service.controller;


import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.entities.Address;
import com.JSR.user_service.service.AddressService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class AddressController {

    private final AddressService addressService;

    @GetMapping("/getAllAddress")
    public List<AddressDTO> getAll() {
        return addressService.getAllAddresses();
    }

    @PostMapping("/addAddress")
    public AddressDTO add(@RequestBody AddressDTO address) {
        return addressService.addAddress(address);
    }

    @PutMapping("/updateAddressById/{id}")
    public AddressDTO update(@PathVariable Long id, @RequestBody AddressDTO address) {
        return addressService.updateAddress(id, address);
    }

    @DeleteMapping("/deleteAddressById/{id}")
    public void delete(@PathVariable Long id) {
        addressService.deleteAddress(id);
    }
}
