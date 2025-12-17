package com.JSR.user_service.dto;

import lombok.*;

import java.util.SimpleTimeZone;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class AddressDTO {

    private Long    id;
    private String  type;
    private String  addressLine1;
    private String  addressLine2;
    private String  city;
    private String  state;
    private String  country;
    private String  zipCode;
    private Boolean isPrimary;

}
