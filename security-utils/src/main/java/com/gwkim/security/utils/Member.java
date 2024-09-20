package com.gwkim.security.utils;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
public class Member {

    private String id;
    private String name;
    private String mobile;


    private List<String> role = new ArrayList<>();
}
