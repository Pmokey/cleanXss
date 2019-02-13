package com.huilan.eps.apply.filter;

import java.util.ArrayList;
import java.util.List;

public class Test {

    public static void main(String[] args) {
        // TODO Auto-generated method stub
        List<String> includeUrls = new ArrayList<String>();
        includeUrls.add("/media/img-lib!scanCodeUpload.action");
        includeUrls.add("123");
        System.out.println(includeUrls.contains("/media/img-lib!scanCodeUpload.action"));
    }
}
