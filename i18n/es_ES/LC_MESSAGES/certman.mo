��    =        S   �      8  �   9     �     �  (   �  1   �     ,     C     O     j  "   �     �     �     �  a   �     A  ?   V     �  
   �     �     �     �     �     �     �  #        %  #   1     U     j  !   �  	   �     �  �   �     [	     `	  "   p	     �	     �	     �	  
   �	     �	  #   �	     �	     �	  F   
     V
  .   ]
  /   �
  <   �
     �
  +     J   ;  3   �     �  	   �     �     �  �  �  x  �       �    �   �     S     [  *   a  -   �     �     �     �     �  %        7     M     b  g   x     �  E   �     A     V     j     y     �     �     �     �  8   �     �  ,        /  &   C  %   j     �     �  �   �     [     b  #   t     �     �     �     �     �  1   �  	        !  Q   9     �  5   �  2   �  C   �     ?  2   ]  M   �  9   �          /     8     J  /  Z  �  �     F     3          2   :                  9   5   !   -   "                                          1   ;                      4   <   )      &          %   0             ,         (                 8   #             *               /      7   	   $       
   6              '         +   .       =          A Certificate Authority is already present on this system. Deleting/Generating/Uploading will invalidate all of your current certificates! Action Admin Are you sure you dont want a passphrase? Are you sure you want to delete this certificate? Can not be left blank! Certificate Certificate Already Exists Certificate Authority Certificate Authority to Reference Certificate List Certificate Management Certificate Manager Certificate Manager for Asterisk. Used for TLS, DTLS connection (think WebRTC and secure traffic) Certificate Settings Certificate to use for this CA (must reference the Private Key) DTLS Rekey Interval DTLS Setup DTLS Verify Delete Delete Certificate Deleted Certificate Description Done! Edit Certificate Authority Settings Enable DTLS Enable or disable DTLS-SRTP support Generate Certificate Generating default CA... Generating default certificate... Host Name I Know what I am doing Interval at which to renegotiate the TLS session and rekey the SRTP session. If this is not set or the value provided is 0 rekeying will be disabled Name New Certificate New Certificate Authority Settings No No Certificates exist Organization Name Passphrase Private Key Private Key File to use for this CA Reset Save Passphrase Select this for additional fields used to upload your own certificate. Submit Successfully deleted the Certificate Authority The Certificate to use from Certificate Manager The Description of this certificate. Used in the module only The Organization Name The Passphrase of the Certificate Authority The base name of the certificate, Can only contain alphanumeric characters This field cannot be blank and must be alphanumeric Update Certificate Upload CA Upload Certificate Use Certificate Verify that provided peer certificate and fingerprint are valid
		<ul>
			<li>A value of 'yes' will perform both certificate and fingerprint verification</li>
			<li>A value of 'no' will perform no certificate or fingerprint verification</li>
			<li>A value of 'fingerprint' will perform ONLY fingerprint verification</li>
			<li>A value of 'certificate' will perform ONLY certficiate verification</li>
			</ul> Whether we are willing to accept connections, connect to the other party, or both.
		This value will be used in the outgoing SDP when offering and for incoming SDP offers when the remote party sends actpass
		<ul>
			<li>active (we want to connect to the other party)</li>
			<li>passive (we want to accept connections only)</li>
			<li>actpass (we will do both)</li>
			</ul> Yes Project-Id-Version: PACKAGE VERSION
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2016-05-06 09:59-0700
PO-Revision-Date: 2016-01-14 22:56+0200
Last-Translator: Ernesto <ecasas@sangoma.com>
Language-Team: Spanish <http://weblate.freepbx.org/projects/freepbx/certman/es_ES/>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Language: es_ES
Plural-Forms: nplurals=2; plural=n != 1;
X-Generator: Weblate 2.2-dev
 Una Autoridad de Certificación ya esta presente en el sistema. Borrar/generar/Bajar invalidara todos sus actuales certificados! Acción Admin ¿Seguro que no quieres una frase de paso? ¿Seguro que quieres borrar este certificado? No se puede dejar en blanco! Certificado Certificado ya existe Autoridad Certificadora Autoridad Certificadora a Referenciar Lista de certificados Gestión Certificado Gestor de Certificado Gestor de Certificado para Asterisk. Usado para TLS, conexión DTLS (piense en WebRTC y trafico seguro) Configuración Certificado Certificado a usar para esta CA (debe referenciar a la Clave Privada) Intervalo Rekey DTLS Configuración DTLS Verificar DTLS Borrar Borrar Certificado Borrar Certificado Descripción Hecho! Editar la configuración de la autoridad del certificado Habilitar DTLS Habilitar o deshabilitar soporte a DTLS-SRTP Generar Certificado Generando Certificado CA por defecto.. Generando Certificados por defecto... Nombre del Host Sé lo que estoy haciendo Intervalo en el que se renegociara  de la sesión TLS y recodificara la sesión SRTP. Si no se establece, o el valor proporcionado es 0 rekeying se desactivará Nombre Nuevo Certificado Ajustes Autoridad nuevo certificado No No existe Certificado Nombre de Organización Palabra Clave Clave Privada Archivo de Clave Privada a ser usado para esta CA Reiniciar Salvar la palabra clave Selecciones este para campos adicionales usados para bajar su propio certificado. Enviar Autoridad de Certificacion satisfactoriamente borrada Certificado a usar desde el Gestor de Certificados La Descripción de este certificado. Usado en el modulo únicamente El Nombre de la Organización La Palabra Clave de la Autoridad de Certificación EL nombre base del certificado. Solo puede contener caracteres alfanuméricos El campo no puede estar en blanco y debe ser alfanumerico Actualizar Certificado Subir CA Subir Certificado Use Certificado Verifique que el certificado pareja proporcionado y la huella digital sean validos↵
→→ <ul> ↵
→→→ <li> Un valor de "sí" llevará a cabo verificación tanto en el certificado como en  la huella digital</li>↵
→→→ <li> Un valor de "no" llevará a cabo ninguna verificación de certificado o de huellas digitales</li>↵
 →→→ <li> Un valor de 'fingerprint' realizará SOLAMENTE verificación de huellas digitales</li>↵
 →→→ <li> Un valor de 'certificate' realizará SOLAMENTE verificación certificado</li>↵
 →→→ </ul> Si estamos dispuestos a aceptar conexiones, conectarse a la otra parte, o ambas.↵
→→ Este valor se utilizará en el SDP saliente al ofrecer y para entrante SDP ofrece cuando la parte remota envía actpass↵
→→ <ul>↵
→→→ <li> activa (queremos conectar a la otra parte) </li> ↵
→→→ <li> pasiva (queremos aceptar sólo conexiones) </li> ↵
→→→ <li> actpass (vamos a hacer las dos cosas) </li> ↵
→→→ </ul> Si 