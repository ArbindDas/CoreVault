package com.JSR.user_service.controller;


import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.entities.Address;
import com.JSR.user_service.service.AddressService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/user/address")
@RequiredArgsConstructor
public class AddressController {

    private final AddressService addressService;

    @GetMapping
    public List<AddressDTO> getAll() {
        return addressService.getAllAddresses();
    }

    @PostMapping
    public AddressDTO add(@RequestBody AddressDTO address) {
        return addressService.addAddress(address);
    }

    @PutMapping("/{id}")
    public AddressDTO update(@PathVariable Long id, @RequestBody AddressDTO address) {
        return addressService.updateAddress(id, address);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) {
        addressService.deleteAddress(id);
    }
}
