/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.exceptions;

/**
 *
 * @author martinhudec
 */
abstract public class MainException extends Exception {

    public MainException(String exceptionMessage) {
        super(exceptionMessage);
    }
}
