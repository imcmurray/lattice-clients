// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'node.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$LatticeEvent {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is LatticeEvent);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'LatticeEvent()';
}


}

/// @nodoc
class $LatticeEventCopyWith<$Res>  {
$LatticeEventCopyWith(LatticeEvent _, $Res Function(LatticeEvent) __);
}


/// Adds pattern-matching-related methods to [LatticeEvent].
extension LatticeEventPatterns on LatticeEvent {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( LatticeEvent_Listening value)?  listening,TResult Function( LatticeEvent_ListeningStopped value)?  listeningStopped,TResult Function( LatticeEvent_PeerConnected value)?  peerConnected,TResult Function( LatticeEvent_Message value)?  message,TResult Function( LatticeEvent_PeerDisconnected value)?  peerDisconnected,TResult Function( LatticeEvent_Error value)?  error,required TResult orElse(),}){
final _that = this;
switch (_that) {
case LatticeEvent_Listening() when listening != null:
return listening(_that);case LatticeEvent_ListeningStopped() when listeningStopped != null:
return listeningStopped(_that);case LatticeEvent_PeerConnected() when peerConnected != null:
return peerConnected(_that);case LatticeEvent_Message() when message != null:
return message(_that);case LatticeEvent_PeerDisconnected() when peerDisconnected != null:
return peerDisconnected(_that);case LatticeEvent_Error() when error != null:
return error(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( LatticeEvent_Listening value)  listening,required TResult Function( LatticeEvent_ListeningStopped value)  listeningStopped,required TResult Function( LatticeEvent_PeerConnected value)  peerConnected,required TResult Function( LatticeEvent_Message value)  message,required TResult Function( LatticeEvent_PeerDisconnected value)  peerDisconnected,required TResult Function( LatticeEvent_Error value)  error,}){
final _that = this;
switch (_that) {
case LatticeEvent_Listening():
return listening(_that);case LatticeEvent_ListeningStopped():
return listeningStopped(_that);case LatticeEvent_PeerConnected():
return peerConnected(_that);case LatticeEvent_Message():
return message(_that);case LatticeEvent_PeerDisconnected():
return peerDisconnected(_that);case LatticeEvent_Error():
return error(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( LatticeEvent_Listening value)?  listening,TResult? Function( LatticeEvent_ListeningStopped value)?  listeningStopped,TResult? Function( LatticeEvent_PeerConnected value)?  peerConnected,TResult? Function( LatticeEvent_Message value)?  message,TResult? Function( LatticeEvent_PeerDisconnected value)?  peerDisconnected,TResult? Function( LatticeEvent_Error value)?  error,}){
final _that = this;
switch (_that) {
case LatticeEvent_Listening() when listening != null:
return listening(_that);case LatticeEvent_ListeningStopped() when listeningStopped != null:
return listeningStopped(_that);case LatticeEvent_PeerConnected() when peerConnected != null:
return peerConnected(_that);case LatticeEvent_Message() when message != null:
return message(_that);case LatticeEvent_PeerDisconnected() when peerDisconnected != null:
return peerDisconnected(_that);case LatticeEvent_Error() when error != null:
return error(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String ticket)?  listening,TResult Function()?  listeningStopped,TResult Function( String peerIdHex)?  peerConnected,TResult Function( String peerIdHex,  String body)?  message,TResult Function( String peerIdHex)?  peerDisconnected,TResult Function( String message)?  error,required TResult orElse(),}) {final _that = this;
switch (_that) {
case LatticeEvent_Listening() when listening != null:
return listening(_that.ticket);case LatticeEvent_ListeningStopped() when listeningStopped != null:
return listeningStopped();case LatticeEvent_PeerConnected() when peerConnected != null:
return peerConnected(_that.peerIdHex);case LatticeEvent_Message() when message != null:
return message(_that.peerIdHex,_that.body);case LatticeEvent_PeerDisconnected() when peerDisconnected != null:
return peerDisconnected(_that.peerIdHex);case LatticeEvent_Error() when error != null:
return error(_that.message);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String ticket)  listening,required TResult Function()  listeningStopped,required TResult Function( String peerIdHex)  peerConnected,required TResult Function( String peerIdHex,  String body)  message,required TResult Function( String peerIdHex)  peerDisconnected,required TResult Function( String message)  error,}) {final _that = this;
switch (_that) {
case LatticeEvent_Listening():
return listening(_that.ticket);case LatticeEvent_ListeningStopped():
return listeningStopped();case LatticeEvent_PeerConnected():
return peerConnected(_that.peerIdHex);case LatticeEvent_Message():
return message(_that.peerIdHex,_that.body);case LatticeEvent_PeerDisconnected():
return peerDisconnected(_that.peerIdHex);case LatticeEvent_Error():
return error(_that.message);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String ticket)?  listening,TResult? Function()?  listeningStopped,TResult? Function( String peerIdHex)?  peerConnected,TResult? Function( String peerIdHex,  String body)?  message,TResult? Function( String peerIdHex)?  peerDisconnected,TResult? Function( String message)?  error,}) {final _that = this;
switch (_that) {
case LatticeEvent_Listening() when listening != null:
return listening(_that.ticket);case LatticeEvent_ListeningStopped() when listeningStopped != null:
return listeningStopped();case LatticeEvent_PeerConnected() when peerConnected != null:
return peerConnected(_that.peerIdHex);case LatticeEvent_Message() when message != null:
return message(_that.peerIdHex,_that.body);case LatticeEvent_PeerDisconnected() when peerDisconnected != null:
return peerDisconnected(_that.peerIdHex);case LatticeEvent_Error() when error != null:
return error(_that.message);case _:
  return null;

}
}

}

/// @nodoc


class LatticeEvent_Listening extends LatticeEvent {
  const LatticeEvent_Listening({required this.ticket}): super._();
  

 final  String ticket;

/// Create a copy of LatticeEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$LatticeEvent_ListeningCopyWith<LatticeEvent_Listening> get copyWith => _$LatticeEvent_ListeningCopyWithImpl<LatticeEvent_Listening>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is LatticeEvent_Listening&&(identical(other.ticket, ticket) || other.ticket == ticket));
}


@override
int get hashCode => Object.hash(runtimeType,ticket);

@override
String toString() {
  return 'LatticeEvent.listening(ticket: $ticket)';
}


}

/// @nodoc
abstract mixin class $LatticeEvent_ListeningCopyWith<$Res> implements $LatticeEventCopyWith<$Res> {
  factory $LatticeEvent_ListeningCopyWith(LatticeEvent_Listening value, $Res Function(LatticeEvent_Listening) _then) = _$LatticeEvent_ListeningCopyWithImpl;
@useResult
$Res call({
 String ticket
});




}
/// @nodoc
class _$LatticeEvent_ListeningCopyWithImpl<$Res>
    implements $LatticeEvent_ListeningCopyWith<$Res> {
  _$LatticeEvent_ListeningCopyWithImpl(this._self, this._then);

  final LatticeEvent_Listening _self;
  final $Res Function(LatticeEvent_Listening) _then;

/// Create a copy of LatticeEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? ticket = null,}) {
  return _then(LatticeEvent_Listening(
ticket: null == ticket ? _self.ticket : ticket // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class LatticeEvent_ListeningStopped extends LatticeEvent {
  const LatticeEvent_ListeningStopped(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is LatticeEvent_ListeningStopped);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'LatticeEvent.listeningStopped()';
}


}




/// @nodoc


class LatticeEvent_PeerConnected extends LatticeEvent {
  const LatticeEvent_PeerConnected({required this.peerIdHex}): super._();
  

 final  String peerIdHex;

/// Create a copy of LatticeEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$LatticeEvent_PeerConnectedCopyWith<LatticeEvent_PeerConnected> get copyWith => _$LatticeEvent_PeerConnectedCopyWithImpl<LatticeEvent_PeerConnected>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is LatticeEvent_PeerConnected&&(identical(other.peerIdHex, peerIdHex) || other.peerIdHex == peerIdHex));
}


@override
int get hashCode => Object.hash(runtimeType,peerIdHex);

@override
String toString() {
  return 'LatticeEvent.peerConnected(peerIdHex: $peerIdHex)';
}


}

/// @nodoc
abstract mixin class $LatticeEvent_PeerConnectedCopyWith<$Res> implements $LatticeEventCopyWith<$Res> {
  factory $LatticeEvent_PeerConnectedCopyWith(LatticeEvent_PeerConnected value, $Res Function(LatticeEvent_PeerConnected) _then) = _$LatticeEvent_PeerConnectedCopyWithImpl;
@useResult
$Res call({
 String peerIdHex
});




}
/// @nodoc
class _$LatticeEvent_PeerConnectedCopyWithImpl<$Res>
    implements $LatticeEvent_PeerConnectedCopyWith<$Res> {
  _$LatticeEvent_PeerConnectedCopyWithImpl(this._self, this._then);

  final LatticeEvent_PeerConnected _self;
  final $Res Function(LatticeEvent_PeerConnected) _then;

/// Create a copy of LatticeEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? peerIdHex = null,}) {
  return _then(LatticeEvent_PeerConnected(
peerIdHex: null == peerIdHex ? _self.peerIdHex : peerIdHex // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class LatticeEvent_Message extends LatticeEvent {
  const LatticeEvent_Message({required this.peerIdHex, required this.body}): super._();
  

 final  String peerIdHex;
 final  String body;

/// Create a copy of LatticeEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$LatticeEvent_MessageCopyWith<LatticeEvent_Message> get copyWith => _$LatticeEvent_MessageCopyWithImpl<LatticeEvent_Message>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is LatticeEvent_Message&&(identical(other.peerIdHex, peerIdHex) || other.peerIdHex == peerIdHex)&&(identical(other.body, body) || other.body == body));
}


@override
int get hashCode => Object.hash(runtimeType,peerIdHex,body);

@override
String toString() {
  return 'LatticeEvent.message(peerIdHex: $peerIdHex, body: $body)';
}


}

/// @nodoc
abstract mixin class $LatticeEvent_MessageCopyWith<$Res> implements $LatticeEventCopyWith<$Res> {
  factory $LatticeEvent_MessageCopyWith(LatticeEvent_Message value, $Res Function(LatticeEvent_Message) _then) = _$LatticeEvent_MessageCopyWithImpl;
@useResult
$Res call({
 String peerIdHex, String body
});




}
/// @nodoc
class _$LatticeEvent_MessageCopyWithImpl<$Res>
    implements $LatticeEvent_MessageCopyWith<$Res> {
  _$LatticeEvent_MessageCopyWithImpl(this._self, this._then);

  final LatticeEvent_Message _self;
  final $Res Function(LatticeEvent_Message) _then;

/// Create a copy of LatticeEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? peerIdHex = null,Object? body = null,}) {
  return _then(LatticeEvent_Message(
peerIdHex: null == peerIdHex ? _self.peerIdHex : peerIdHex // ignore: cast_nullable_to_non_nullable
as String,body: null == body ? _self.body : body // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class LatticeEvent_PeerDisconnected extends LatticeEvent {
  const LatticeEvent_PeerDisconnected({required this.peerIdHex}): super._();
  

 final  String peerIdHex;

/// Create a copy of LatticeEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$LatticeEvent_PeerDisconnectedCopyWith<LatticeEvent_PeerDisconnected> get copyWith => _$LatticeEvent_PeerDisconnectedCopyWithImpl<LatticeEvent_PeerDisconnected>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is LatticeEvent_PeerDisconnected&&(identical(other.peerIdHex, peerIdHex) || other.peerIdHex == peerIdHex));
}


@override
int get hashCode => Object.hash(runtimeType,peerIdHex);

@override
String toString() {
  return 'LatticeEvent.peerDisconnected(peerIdHex: $peerIdHex)';
}


}

/// @nodoc
abstract mixin class $LatticeEvent_PeerDisconnectedCopyWith<$Res> implements $LatticeEventCopyWith<$Res> {
  factory $LatticeEvent_PeerDisconnectedCopyWith(LatticeEvent_PeerDisconnected value, $Res Function(LatticeEvent_PeerDisconnected) _then) = _$LatticeEvent_PeerDisconnectedCopyWithImpl;
@useResult
$Res call({
 String peerIdHex
});




}
/// @nodoc
class _$LatticeEvent_PeerDisconnectedCopyWithImpl<$Res>
    implements $LatticeEvent_PeerDisconnectedCopyWith<$Res> {
  _$LatticeEvent_PeerDisconnectedCopyWithImpl(this._self, this._then);

  final LatticeEvent_PeerDisconnected _self;
  final $Res Function(LatticeEvent_PeerDisconnected) _then;

/// Create a copy of LatticeEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? peerIdHex = null,}) {
  return _then(LatticeEvent_PeerDisconnected(
peerIdHex: null == peerIdHex ? _self.peerIdHex : peerIdHex // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class LatticeEvent_Error extends LatticeEvent {
  const LatticeEvent_Error({required this.message}): super._();
  

 final  String message;

/// Create a copy of LatticeEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$LatticeEvent_ErrorCopyWith<LatticeEvent_Error> get copyWith => _$LatticeEvent_ErrorCopyWithImpl<LatticeEvent_Error>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is LatticeEvent_Error&&(identical(other.message, message) || other.message == message));
}


@override
int get hashCode => Object.hash(runtimeType,message);

@override
String toString() {
  return 'LatticeEvent.error(message: $message)';
}


}

/// @nodoc
abstract mixin class $LatticeEvent_ErrorCopyWith<$Res> implements $LatticeEventCopyWith<$Res> {
  factory $LatticeEvent_ErrorCopyWith(LatticeEvent_Error value, $Res Function(LatticeEvent_Error) _then) = _$LatticeEvent_ErrorCopyWithImpl;
@useResult
$Res call({
 String message
});




}
/// @nodoc
class _$LatticeEvent_ErrorCopyWithImpl<$Res>
    implements $LatticeEvent_ErrorCopyWith<$Res> {
  _$LatticeEvent_ErrorCopyWithImpl(this._self, this._then);

  final LatticeEvent_Error _self;
  final $Res Function(LatticeEvent_Error) _then;

/// Create a copy of LatticeEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? message = null,}) {
  return _then(LatticeEvent_Error(
message: null == message ? _self.message : message // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on
