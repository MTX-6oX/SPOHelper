package org.homework;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Helper {

    public static Properties prop = loadProps();

    public static String config(String key) {
        String result = null;
        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream("C:/data/edit.properties")) {
            props.load(in);
            //in.close();
            result = props.getProperty(key);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static Properties loadProps() {
        try (InputStream input = Helper.class.getClassLoader().getResourceAsStream("config.properties")) {

            Properties prop = new Properties();

            if (input == null) {
                System.out.println("Sorry, unable to find config.properties");
                return null;
            }

            //load a properties file from class path, inside static method
            prop.load(input);

            return prop;

        } catch (IOException ex) {
            ex.printStackTrace();
            return null;
        }
    }

}
